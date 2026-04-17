const express = require("express");
const router = express.Router();
const { register, login, me } = require("../controllers/auth.controllers");
const { googleAuth } = require("../controllers/googleAuth.controllers");
const { githubAuth } = require("../controllers/githubAuth.controllers");
const auth = require("../middleware/auth.middleware");

router.post("/register", register);
router.post("/login", login);
router.post("/google", googleAuth);
router.post("/github", githubAuth);
router.get("/me", auth, me);

module.exports = router;