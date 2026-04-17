const express = require("express");
const router = express.Router();

const auth = require("../middleware/auth.middleware");
const {
  analyzeRepository,
  aiScanRepository,
  malwareCheckRepository,
  malwareZipScanRepository,
  malwareCombinedScanRepository,
  malwarePipelineScanRepository,
} = require("../controllers/repo.controllers");

router.post("/analyze", auth, analyzeRepository);
router.post("/ai-scan", auth, aiScanRepository);
router.post("/malware-check", auth, malwareCheckRepository);
router.post("/malware-zip-scan", auth, malwareZipScanRepository);
router.post("/malware-combined-scan", auth, malwareCombinedScanRepository);
router.post("/malware-pipeline-scan", auth, malwarePipelineScanRepository);

module.exports = router;
