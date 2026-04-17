const axios = require("axios");
const jwt = require("jsonwebtoken");
const User = require("../models/user.models");

const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";
const GITHUB_EMAILS_URL = "https://api.github.com/user/emails";

const sanitizeUsername = (value) =>
    value
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "");

const generateUsername = async (email, preferred) => {
    const emailBase = email.split("@")[0] || "user";
    const candidateBase = sanitizeUsername(preferred || emailBase) || "user";
    let username = candidateBase;

    while (await User.findOne({ username })) {
        const rand = Math.floor(100 + Math.random() * 900);
        username = `${candidateBase}${rand}`;
    }

    return username;
};

const selectVerifiedEmail = (emails) => {
    if (!Array.isArray(emails)) return null;

    const primaryVerified = emails.find(
        (item) => item && item.primary && item.verified && typeof item.email === "string",
    );
    if (primaryVerified) return primaryVerified.email;

    const firstVerified = emails.find(
        (item) => item && item.verified && typeof item.email === "string",
    );
    return firstVerified ? firstVerified.email : null;
};

exports.githubAuth = async (req, res) => {
    try {
        const { code, redirectUri } = req.body;

        if (!code) {
            return res.status(400).json({ message: "GitHub authorization code is required" });
        }

        const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
        const clientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET;

        if (!clientId || !clientSecret) {
            return res.status(500).json({
                message: "GitHub OAuth is not configured",
            });
        }

        const tokenResponse = await axios.post(
            GITHUB_TOKEN_URL,
            {
                client_id: clientId,
                client_secret: clientSecret,
                code,
                redirect_uri: redirectUri,
            },
            {
                headers: {
                    Accept: "application/json",
                },
            },
        );

        const accessToken = tokenResponse.data && tokenResponse.data.access_token;
        if (!accessToken) {
            return res.status(401).json({ message: "Invalid or expired GitHub authorization code" });
        }

        const [profileResponse, emailsResponse] = await Promise.all([
            axios.get(GITHUB_USER_URL, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    Accept: "application/vnd.github+json",
                },
            }),
            axios.get(GITHUB_EMAILS_URL, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    Accept: "application/vnd.github+json",
                },
            }),
        ]);

        const profile = profileResponse.data || {};
        const githubId = profile.id ? String(profile.id) : null;
        const login = typeof profile.login === "string" ? profile.login : null;
        const publicEmail = typeof profile.email === "string" ? profile.email : null;
        const verifiedEmail = selectVerifiedEmail(emailsResponse.data);
        const email = (publicEmail || verifiedEmail || "").trim().toLowerCase();

        if (!githubId || !email) {
            return res.status(400).json({
                message: "GitHub account does not provide a verified email address",
            });
        }

        let user = await User.findOne({
            $or: [{ githubId }, { email }],
        });

        if (!user) {
            const username = await generateUsername(email, login);
            user = await User.create({
                username,
                email,
                githubId,
            });
        }

        if (!user.githubId) {
            user.githubId = githubId;
            await user.save();
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        return res.json({
            id: user._id,
            username: user.username,
            email: user.email,
            token,
        });
    } catch (err) {
        console.error(err);

        if (err.response) {
            const status = err.response.status;

            if (status === 401) {
                return res.status(401).json({ message: "Invalid GitHub access token" });
            }

            if (status === 422) {
                return res.status(400).json({ message: "Invalid GitHub OAuth request" });
            }
        }

        return res.status(500).json({ message: "GitHub authentication failed" });
    }
};
