const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const User = require("../models/user.models");

const normalizeEmail = (value) => {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
};

const looksLikeBcryptHash = (value) => {
    return typeof value === "string" && /^\$2[aby]\$\d{2}\$/.test(value);
};


const generateToken = (id) => {
    return jwt.sign({id},process.env.JWT_SECRET,{expiresIn:"7d"});
}

exports.register = async (req,res) => {
    try{
        const {username,email,password} = req.body;
        const normalizedEmail = normalizeEmail(email);
        const normalizedUsername = typeof username === "string" ? username.trim() : "";

        if (!normalizedUsername || !normalizedEmail || !password) {
            return res.status(400).json({ message: "username, email, and password are required" });
        }

        const userExist = await User.findOne({email: normalizedEmail});

        if(userExist){
            return res.status(409).json({message:"User already exist"});
        }

        const hashPassword = await bcrypt.hash(password,10);
        
        const user = await User.create({
            username: normalizedUsername,
            email: normalizedEmail,
            password:hashPassword
        })

        res.status(201).json({
            id:user._id,
            username:user.username,
            email:user.email,
            token:generateToken(user._id)
        })

    }catch(err){
        if (err && err.code === 11000) {
            const keyValue = err.keyValue && typeof err.keyValue === "object" ? err.keyValue : null;
            const field = keyValue ? Object.keys(keyValue)[0] : null;
            const message = field ? `${field} already exists` : "User already exists";
            return res.status(400).json({ message });
        }
        console.error("Register error:", err);
        res.status(500).json({
            message: err.message,
            ...(process.env.NODE_ENV !== "production" ? { stack: err.stack } : {})
        });
    }
};


exports.login = async (req,res) => {
    try{
        const {email,password} = req.body;
        const normalizedEmail = normalizeEmail(email);

        if (!normalizedEmail || !password) {
            return res.status(400).json({ message: "email and password are required" });
        }

        const user = await User.findOne({email: normalizedEmail});

        if(!user){
            return res.status(401).json({message:"Invalid email or password"});
        }

        if (typeof user.password !== "string" || user.password.length === 0) {
            return res.status(401).json({message:"This account uses social login. Please continue with Google/GitHub."});
        }

        let IsMatch = false;
        if (looksLikeBcryptHash(user.password)) {
            IsMatch = await bcrypt.compare(password, user.password);
        } else {
            // Legacy plaintext fallback: allow login once, then upgrade hash.
            IsMatch = password === user.password;
            if (IsMatch) {
                user.password = await bcrypt.hash(password, 10);
                await user.save();
            }
        }

        if(!IsMatch){
            return res.status(401).json({message:"Invalid email or password"});
        }

        res.json({
            id:user._id,
            username:user.username,
            email:user.email,
            token:generateToken(user._id)
        });

    }catch(err){
        console.error("Login error:", err);
        res.status(500).json({
            message: err.message,
            ...(process.env.NODE_ENV !== "production" ? { stack: err.stack } : {})
        });
    }
};