const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");

const app = express();
// Load env vars from server/.env only (do not use .env.local)
dotenv.config({ path: path.join(__dirname, ".env") });

const defaultAllowedOrigins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
];
const envAllowedOrigins = String(process.env.FRONTEND_URL || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
const allowedOrigins = new Set(envAllowedOrigins.length > 0 ? envAllowedOrigins : defaultAllowedOrigins);
const allowPrivateNetworkOrigins = process.env.CORS_ALLOW_PRIVATE_NETWORK !== "0";

function isPrivateNetworkHost(hostname) {
    const host = String(hostname || "").trim().toLowerCase();
    if (!host) return false;
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    return false;
}

function isAllowedOrigin(origin) {
    if (!origin) return true;
    if (allowedOrigins.has(origin)) return true;

    if (!allowPrivateNetworkOrigins) return false;

    try {
        const parsed = new URL(origin);
        const isHttp = parsed.protocol === "http:" || parsed.protocol === "https:";
        return isHttp && isPrivateNetworkHost(parsed.hostname);
    } catch {
        return false;
    }
}

app.use(
    cors({
        origin(origin, callback) {
            if (isAllowedOrigin(origin)) return callback(null, true);

            // Do not throw; this avoids noisy stack traces for preflight requests.
            console.warn(`CORS blocked origin: ${origin}`);
            return callback(null, false);
        },
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: true,
    }),
);

app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()") ;
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self';");
    next();
});

app.use(express.json());

app.use("/api/auth",require("./routes/auth.routes"))
app.use("/api/repo",require("./routes/repo.routes"))

app.get('/',(req,res)=>{
    res.send("Homepage is working");
})


const connectDB = require("./config/dB")
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";

connectDB()
    .then(() => {
        app.listen(PORT, HOST, ()=>{
            console.log(`Server is listening at ${HOST}:${PORT}`);
        })
    })
    .catch(() => {
        process.exit(1);
    });