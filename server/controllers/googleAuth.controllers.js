const User = require("../models/users.models");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const generateUsername = async (email) => {
    const base = email.split("@")[0];
    let username = base;

    while (await User.findOne({ username })) {
        const rand = Math.floor(100 + Math.random() * 900);
        username = `${base}${rand}`;
    }

    return username;
};

exports.googleAuth = async (req, res) => {
    try {
        const { access_token } = req.body; // received from frontend

        if (!access_token) {
            return res.status(400).json({ message: "Google Access token required" });
        }

        // Fetch user profile
        const response = await axios.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            {
                headers: {
                    Authorization: `Bearer ${access_token}`,
                },
            }
        );

        const { email, email_verified, sub } = response.data;
        if (!email_verified) {
            return res.status(400).json({
                message: "Google email not verified",
            });
        }

        let user = await User.findOne({
            $or: [{ googleId: sub }, { email }],
        });

        if (!user) {
            const username = await generateUsername(email);

            user = await User.create({
                username,
                email,
                googleId: sub,
            });
        }

        // If user exists but doesn't have googleId, link it
        if (user && !user.googleId) {
            user.googleId = sub;
            await user.save();
        }

        // Generate JWT
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        res.json({
            id: user._id,
            username: user.username,
            email: user.email,
            token,
        });
    } catch (err) {
        console.error(err);

        // If error came from Google API
        if (err.response) {
            const status = err.response.status;

            if (status === 401) {
                return res.status(401).json({
                    message: "Invalid or expired Google access token",
                });
            }

            if (status === 400) {
                return res.status(400).json({
                    message: "Invalid Google authentication request",
                });
            }
        }

        // Unexpected server error
        res.status(500).json({
            message: "Google authentication failed",
        });
    }
};