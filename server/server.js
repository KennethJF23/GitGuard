const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");

const app = express();
// Load env vars from server/.env only (do not use .env.local)
dotenv.config({ path: path.join(__dirname, ".env") });

const defaultAllowedOrigins = ["http://localhost:3000", "http://127.0.0.1:3000"];
const envAllowedOrigins = String(process.env.FRONTEND_URL || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
const allowedOrigins = new Set(envAllowedOrigins.length > 0 ? envAllowedOrigins : defaultAllowedOrigins);

app.use(
    cors({
        origin(origin, callback) {
            if (!origin) return callback(null, true);
            if (allowedOrigins.has(origin)) return callback(null, true);
            return callback(new Error("CORS origin not allowed"));
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