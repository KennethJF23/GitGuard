const express = require("express");
const router = express.Router();
const { register, login } = require("../controllers/auth.controllers");
const { googleAuth } = require("../controllers/googleAuth.controllers");
const { githubAuth } = require("../controllers/githubAuth.controllers");

router.post("/register", register);
router.post("/login", login);
router.post("/google", googleAuth);
router.post("/github", githubAuth);

module.exports = router;