const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const fsp = require("fs/promises");
const { pipeline } = require("stream/promises");

const axios = require("axios");
const unzipper = require("unzipper");
const mongoose = require("mongoose");

const { redisGetJson, redisSetJson } = require("../config/redis");
const MalwareKeyword = require("../models/malwareKeywords.models");
const { scanGithubRepoForMalwarePipeline } = require("../services/malwareScanPipeline");
const {
  detectRepositoryLicense,
  generateMalwareExplanation,
  applyContextAwareRiskAdjustments,
  generateAIInsights,
  generateTrustReport,
} = require("../services/intelligence.service");
const { analyzeUserProfileAndCommits } = require("../services/userContributionAnomaly.service");

// In-memory cache to avoid repeated MongoDB calls.
// This is process-local (each Node instance caches independently).
let malwareKeywordCache = {
  loadedAtMs: 0,
  ttlMs: 5 * 60 * 1000,
  docs: null,
  compiled: null,
};

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function getGitHubApiConfig() {
  const base = process.env.GITHUB_API_BASE;
  const version = process.env.GITHUB_API_VERSION;

  if (!isNonEmptyString(base)) {
    const err = new Error(
      "GitHub API is not configured. Set GITHUB_API_BASE in server/.env.",
    );
    err.statusCode = 500;
    throw err;
  }

  if (!isNonEmptyString(version)) {
    const err = new Error(
      "GitHub API is not configured. Set GITHUB_API_VERSION in server/.env.",
    );
    err.statusCode = 500;
    throw err;
  }

  return {
    base: base.trim().replace(/\/+$/, ""),
    version: version.trim(),
  };
}

function badRequest(message) {
  const err = new Error(message);
  err.statusCode = 400;
  return err;
}

function safeNumber(value, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function getMalwareRiskLevelFromNormalized(normalizedRiskScore) {
  const n = clamp(safeNumber(normalizedRiskScore, 0), 0, 100);
  if (n >= 75) return "CRITICAL";
  if (n >= 50) return "HIGH";
  if (n >= 25) return "MODERATE";
  return "LOW";
}

function buildMalwareRiskMetrics(totalScore) {
  const roundedScore = Math.round(safeNumber(totalScore, 0) * 100) / 100;
  const normalizedRiskScore = Math.round(clamp((roundedScore / 25) * 100, 0, 100));
  return {
    totalRiskScore: roundedScore,
    normalizedRiskScore,
    riskLevel: getMalwareRiskLevelFromNormalized(normalizedRiskScore),
  };
}

function daysBetween(isoDateA, isoDateB) {
  const a = new Date(isoDateA).getTime();
  const b = new Date(isoDateB).getTime();
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  const deltaMs = Math.abs(b - a);
  return Math.floor(deltaMs / (1000 * 60 * 60 * 24));
}

function parseGithubRepoInput(input) {
  if (!isNonEmptyString(input)) {
    throw badRequest("Please provide a GitHub repository URL.");
  }

  const trimmed = input.trim();

  // Allow shorthand "owner/repo".
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
    const parts = trimmed.replace(/^github\.com\//i, "").split("/").filter(Boolean);
    if (parts.length >= 2) {
      return {
        owner: parts[0],
        repo: parts[1].replace(/\.git$/i, ""),
      };
    }
    throw badRequest(
      "Invalid input. Use a full GitHub URL like https://github.com/owner/repo",
    );
  }

  let url;
  try {
    url = new URL(trimmed);
  } catch {
    throw badRequest("Invalid URL. Please paste a valid GitHub repository link.");
  }

  if (!/^(www\.)?github\.com$/i.test(url.hostname)) {
    throw badRequest("Only github.com repository links are supported.");
  }

  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length < 2) {
    throw badRequest("Invalid GitHub repository URL. Expected /owner/repo");
  }

  const owner = segments[0];
  const repo = segments[1].replace(/\.git$/i, "");

  if (!owner || !repo) {
    throw badRequest("Invalid GitHub repository URL. Expected /owner/repo");
  }

  return { owner, repo };
}

function parseGithubUsernameInput(input) {
  if (!isNonEmptyString(input)) {
    throw badRequest("Please provide a GitHub username or profile URL.");
  }

  const raw = input.trim();

  // Accept plain username.
  if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
    const cleaned = raw.replace(/^github\.com\//i, "").replace(/^@/, "").split("/").filter(Boolean)[0] || "";
    if (!cleaned) {
      throw badRequest("Invalid GitHub username input.");
    }
    return cleaned;
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw badRequest("Invalid URL. Please provide a valid GitHub profile link.");
  }

  if (!/^(www\.)?github\.com$/i.test(url.hostname)) {
    throw badRequest("Only github.com user profiles are supported.");
  }

  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length < 1) {
    throw badRequest("Invalid GitHub profile URL. Expected /username");
  }

  return segments[0].replace(/^@/, "");
}

function computeMedian(values) {
  const list = (Array.isArray(values) ? values : [])
    .map((value) => safeNumber(value, NaN))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);

  if (list.length === 0) return 0;
  const mid = Math.floor(list.length / 2);
  if (list.length % 2 === 0) {
    return (list[mid - 1] + list[mid]) / 2;
  }
  return list[mid];
}

function computeCollaboratorDeterministicScore(profile, baselines) {
  const totalContributions = safeNumber(baselines.totalContributions, 1);
  const medianContributions = Math.max(1, safeNumber(baselines.medianContributions, 0));

  const lifetimeContributions = safeNumber(profile.lifetimeContributions, 0);
  const contributionShare = lifetimeContributions / totalContributions;
  const contributionRatioToMedian = lifetimeContributions / (medianContributions + 1);

  const suspiciousMessageRatio = safeNumber(profile.suspiciousMessageRatio, 0);
  const nightCommitRatio = safeNumber(profile.nightCommitRatio, 0);
  const weekendCommitRatio = safeNumber(profile.weekendCommitRatio, 0);
  const recencyBurstRatio = safeNumber(profile.recencyBurstRatio, 0);

  let score = 0;

  if (contributionShare >= 0.55) score += 28;
  else if (contributionShare >= 0.4) score += 18;
  else if (contributionShare >= 0.25) score += 10;

  if (contributionRatioToMedian >= 6) score += 24;
  else if (contributionRatioToMedian >= 4) score += 16;
  else if (contributionRatioToMedian >= 2.5) score += 8;

  if (suspiciousMessageRatio >= 0.25) score += 18;
  else if (suspiciousMessageRatio >= 0.15) score += 10;

  if (nightCommitRatio >= 0.7) score += 12;
  else if (nightCommitRatio >= 0.5) score += 6;

  if (weekendCommitRatio >= 0.75) score += 8;

  if (recencyBurstRatio >= 0.7) score += 10;
  else if (recencyBurstRatio >= 0.5) score += 5;

  const normalizedScore = clamp(Math.round(score), 0, 100);
  let riskLevel = "LOW";
  if (normalizedScore >= 70) riskLevel = "HIGH";
  else if (normalizedScore >= 40) riskLevel = "MEDIUM";

  const reasons = [];
  if (contributionShare >= 0.4) reasons.push("Single collaborator contributes a dominant share of total commits");
  if (contributionRatioToMedian >= 4) reasons.push("Contribution volume is far above collaborator baseline");
  if (suspiciousMessageRatio >= 0.15) reasons.push("Commit messages include risky or low-quality patterns");
  if (nightCommitRatio >= 0.5) reasons.push("Large share of commits happen during night UTC hours");
  if (recencyBurstRatio >= 0.5) reasons.push("Recent contribution spike is unusually concentrated");

  return {
    score: normalizedScore,
    riskLevel,
    reasons: reasons.slice(0, 5),
    contributionShare: Math.round(contributionShare * 1000) / 1000,
    contributionRatioToMedian: Math.round(contributionRatioToMedian * 1000) / 1000,
  };
}

function buildCollaboratorCommitSignals(commits) {
  const suspiciousMessageRegexes = [
    /\b(temp|tmp|quick fix|hack|bypass|disable\s+auth|disable\s+security)\b/i,
    /\b(debug\s+only|remove\s+checks|skip\s+validation|hotfix\s+prod)\b/i,
    /\b(wip|test\s+commit|trial|dummy)\b/i,
  ];

  const list = Array.isArray(commits) ? commits : [];
  if (list.length === 0) {
    return {
      analyzedCommits: 0,
      suspiciousMessageRatio: 0,
      nightCommitRatio: 0,
      weekendCommitRatio: 0,
      recencyBurstRatio: 0,
      lastCommitAt: null,
    };
  }

  let suspiciousCount = 0;
  let nightCount = 0;
  let weekendCount = 0;

  let latestTs = null;
  const dayBuckets = new Map();

  for (const commit of list) {
    const commitObj = commit && typeof commit.commit === "object" ? commit.commit : null;
    const message = commitObj && typeof commitObj.message === "string" ? commitObj.message : "";
    const authored =
      commitObj && commitObj.author && typeof commitObj.author === "object" && typeof commitObj.author.date === "string"
        ? commitObj.author.date
        : null;

    if (suspiciousMessageRegexes.some((re) => re.test(message))) {
      suspiciousCount += 1;
    }

    if (authored) {
      const authoredTs = new Date(authored).getTime();
      if (Number.isFinite(authoredTs)) {
        if (latestTs === null || authoredTs > latestTs) latestTs = authoredTs;
      }

      const authoredDate = new Date(authored);
      const hour = authoredDate.getUTCHours();
      const day = authoredDate.getUTCDay();

      if (hour < 6) nightCount += 1;
      if (day === 0 || day === 6) weekendCount += 1;

      const key = authored.slice(0, 10);
      dayBuckets.set(key, (dayBuckets.get(key) || 0) + 1);
    }
  }

  const dailyCounts = Array.from(dayBuckets.values());
  const medianDaily = computeMedian(dailyCounts);
  const burstThreshold = Math.max(2, Math.round(Math.max(1, medianDaily) * 1.8));
  const burstDays = dailyCounts.filter((count) => count >= burstThreshold).length;

  const total = list.length;

  return {
    analyzedCommits: total,
    suspiciousMessageRatio: suspiciousCount / total,
    nightCommitRatio: nightCount / total,
    weekendCommitRatio: weekendCount / total,
    recencyBurstRatio: dayBuckets.size > 0 ? burstDays / dayBuckets.size : 0,
    lastCommitAt: latestTs !== null ? new Date(latestTs).toISOString() : null,
  };
}

function buildGitHubApiUrl(path, query) {
  const { base } = getGitHubApiConfig();
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(normalizedPath, base);
  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null) continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

function getAnalyzeCacheTtlSeconds() {
  const raw = process.env.REDIS_ANALYZE_TTL_SECONDS;
  if (!isNonEmptyString(raw)) return 3600;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 3600;
  return Math.floor(parsed);
}

function getAiScanCacheTtlSeconds() {
  const raw = process.env.REDIS_AI_SCAN_TTL_SECONDS;
  if (!isNonEmptyString(raw)) return 900;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 900;
  return Math.floor(parsed);
}

function buildAnalyzeCacheKey(owner, repo) {
  const baseKey = `analyze:v1:${String(owner).toLowerCase()}/${String(repo).toLowerCase()}`;
  // Hash to keep keys short and safe.
  const digest = crypto.createHash("sha256").update(baseKey).digest("hex");
  return `analyze:v1:${digest}`;
}

function buildAiScanCacheKey(owner, repo, model) {
  const baseKey = `ai-scan:v1:${String(owner).toLowerCase()}/${String(repo).toLowerCase()}:${String(model || "").toLowerCase()}`;
  const digest = crypto.createHash("sha256").update(baseKey).digest("hex");
  return `ai-scan:v1:${digest}`;
}

function getMalwareScanCacheTtlSeconds() {
  const raw = process.env.REDIS_MALWARE_SCAN_TTL_SECONDS;
  if (!isNonEmptyString(raw)) return 900;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 900;
  return Math.floor(parsed);
}

function buildMalwareScanCacheKey(owner, repo) {
  // v2: includes deterministic verdict in payload.
  const baseKey = `malware-scan:v2:${String(owner).toLowerCase()}/${String(repo).toLowerCase()}`;
  const digest = crypto.createHash("sha256").update(baseKey).digest("hex");
  return `malware-scan:v2:${digest}`;
}

function getMalwarePipelineCacheTtlSeconds() {
  const raw = process.env.REDIS_MALWARE_PIPELINE_TTL_SECONDS;
  if (!isNonEmptyString(raw)) return 600;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 600;
  return Math.floor(parsed);
}

function buildMalwarePipelineCacheKey(owner, repo) {
  const baseKey = `malware-pipeline:v2:${String(owner).toLowerCase()}/${String(repo).toLowerCase()}`;
  const digest = crypto.createHash("sha256").update(baseKey).digest("hex");
  return `malware-pipeline:v2:${digest}`;
}

function textIncludesAny(haystack, needles) {
  if (!isNonEmptyString(haystack) || !Array.isArray(needles) || needles.length === 0) return false;
  const text = safeLower(haystack);
  return needles.some((n) => isNonEmptyString(n) && text.includes(safeLower(n)));
}

function computeMalwareVerdict({ totalScore, matches, repoMeta, readmeText, filePathsText, aiParsed }) {
  const roundedScore = Math.round(safeNumber(totalScore, 0) * 100) / 100;
  const matchList = Array.isArray(matches) ? matches : [];
  const categories = new Set(matchList.map((m) => (m && typeof m.category === "string" ? m.category : "generic")));

  const topics = Array.isArray(repoMeta && repoMeta.topics) ? repoMeta.topics.join(" ") : "";
  const description = repoMeta && typeof repoMeta.description === "string" ? repoMeta.description : "";
  const repoName = repoMeta && (repoMeta.full_name || repoMeta.name) ? String(repoMeta.full_name || repoMeta.name) : "";
  const combinedMetaText = [repoName, topics, description, readmeText].filter(Boolean).join("\n");
  const filePathCorpus = isNonEmptyString(filePathsText) ? String(filePathsText) : "";

  const datasetTerms = [
    "dataset",
    "datasets",
    "sample",
    "samples",
    "collection",
    "corpus",
    "training data",
    "ioc",
    "iocs",
    "indicator",
    "indicators",
    "signatures",
  ];
  const malwareTerms = [
    "malware",
    "ransomware",
    "stealer",
    "botnet",
    "trojan",
    "virus",
    "payload",
    "backdoor",
    "keylogger",
    "rat",
    "spyware",
    "phishing",
    "exploit",
    "c2",
    "command and control",
  ];

  const fileSignals = [".exe", ".dll", ".apk", ".bin", ".scr"];
  const hasSuspiciousFiles = fileSignals.some((ext) => safeLower(filePathCorpus).includes(ext));

  const datasetSignal =
    (textIncludesAny(combinedMetaText, datasetTerms) && textIncludesAny(combinedMetaText, malwareTerms)) ||
    (hasSuspiciousFiles && textIncludesAny(combinedMetaText, ["sample", "samples", "collection"]));

  const highSignalCategories = new Set([
    "combination_high_risk",
    "credential_access",
    "keylogging",
    "data_exfiltration",
    "command_execution",
    "persistence",
  ]);

  const hasHighSignalCategory = Array.from(highSignalCategories).some((c) => categories.has(c));
  const hasCombinationHighRisk = categories.has("combination_high_risk");
  const matchCount = matchList.length;

  let level = "SAFE";
  const reasons = [];

  // Priority 1: MALICIOUS
  if (roundedScore >= 10 || hasCombinationHighRisk || (hasHighSignalCategory && roundedScore >= 4)) {
    level = "MALICIOUS";
    reasons.push("Strong malicious indicators detected.");
    if (roundedScore >= 10) reasons.push("High aggregate indicator score.");
    if (hasCombinationHighRisk) reasons.push("High-risk indicator combination detected.");
    if (hasHighSignalCategory) reasons.push("High-signal categories matched (execution/exfil/credentials/etc.).");
  }

  // Priority 2: DANGEROUS_DATASET (independent of score)
  else if (datasetSignal) {
    level = "DANGEROUS_DATASET";
    reasons.push("Repository contains malware samples or dataset.");
    if (hasSuspiciousFiles) reasons.push("Suspicious file extensions appear in repository paths.");
  }

  // Priority 3: SUSPICIOUS
  else if (roundedScore >= 3 || matchCount >= 3) {
    level = "SUSPICIOUS";
    reasons.push("Multiple suspicious indicators matched.");
  }

  // Default: SAFE
  else {
    reasons.push("Few or no indicators matched.");
  }

  const aiMalicious = aiParsed && typeof aiParsed.malicious === "boolean" ? aiParsed.malicious : null;
  const aiConfidence = aiParsed && typeof aiParsed.confidence === "number" ? aiParsed.confidence : null;
  if (aiMalicious === true && typeof aiConfidence === "number" && aiConfidence >= 0.7 && level !== "MALICIOUS") {
    level = "MALICIOUS";
    reasons.push("AI verdict indicated malicious (high confidence).");
  }

  const mapping = {
    SAFE: { label: "SAFE", emoji: "🟢" },
    SUSPICIOUS: { label: "SUSPICIOUS", emoji: "🟡" },
    MALICIOUS: { label: "MALICIOUS", emoji: "🔴" },
    DANGEROUS_DATASET: { label: "DANGEROUS DATASET", emoji: "🟠" },
  };

  const view = mapping[level] || mapping.SAFE;
  return {
    level,
    label: view.label,
    emoji: view.emoji,
    score: roundedScore,
    reasons: reasons.filter(Boolean).slice(0, 5),
  };
}

function safeLower(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function buildMetadataCorpus({ repoMeta, languages, readmeText, treeInfo }) {
  const topics = Array.isArray(repoMeta && repoMeta.topics) ? repoMeta.topics : [];
  const languageNames = languages && typeof languages === "object" ? Object.keys(languages) : [];
  const filePaths = Array.isArray(treeInfo && treeInfo.paths) ? treeInfo.paths : [];

  // Keep payload bounded.
  const cappedPaths = filePaths.slice(0, 500);
  const cappedReadme = typeof readmeText === "string" ? readmeText.slice(0, 12000) : "";

  return {
    name: [repoMeta && repoMeta.full_name, repoMeta && repoMeta.name].filter(Boolean).join(" "),
    description: repoMeta && repoMeta.description ? String(repoMeta.description) : "",
    homepage: repoMeta && repoMeta.homepage ? String(repoMeta.homepage) : "",
    topics: topics.join(" "),
    languages: languageNames.join(" "),
    readme: cappedReadme,
    filePaths: cappedPaths.join("\n"),
  };
}

function keywordMatchesCorpus(keyword, corpusByField) {
  if (!keyword || typeof keyword !== "object") return { matched: false, fields: [] };

  const pattern = typeof keyword.pattern === "string" ? keyword.pattern.trim() : "";
  if (!pattern) return { matched: false, fields: [] };

  const mode = keyword.matchMode === "regex" ? "regex" : "substring";
  const fieldsMatched = [];

  if (mode === "regex") {
    let re;
    try {
      re = new RegExp(pattern, "i");
    } catch {
      return { matched: false, fields: [] };
    }

    for (const [field, text] of Object.entries(corpusByField)) {
      if (typeof text !== "string" || !text) continue;
      if (re.test(text)) fieldsMatched.push(field);
    }

    return { matched: fieldsMatched.length > 0, fields: fieldsMatched };
  }

  const needle = safeLower(pattern);
  if (!needle) return { matched: false, fields: [] };

  for (const [field, text] of Object.entries(corpusByField)) {
    if (typeof text !== "string" || !text) continue;
    if (safeLower(text).includes(needle)) fieldsMatched.push(field);
  }

  return { matched: fieldsMatched.length > 0, fields: fieldsMatched };
}

function tryParseJsonObject(text) {
  if (!isNonEmptyString(text)) return null;
  const trimmed = text.trim();
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end < 0 || end <= start) return null;
  try {
    const parsed = JSON.parse(trimmed.slice(start, end + 1));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function getOpenRouterApiKey() {
  const key = process.env.OPENROUTER_API_KEY || process.env.openrouter_api_key;
  if (!isNonEmptyString(key)) {
    const err = new Error(
      "OpenRouter is not configured. Set OPENROUTER_API_KEY in server/.env.",
    );
    err.statusCode = 500;
    throw err;
  }
  return key.trim();
}

function getOpenRouterModels() {
  const rawList = process.env.OPENROUTER_MODELS || process.env.openrouter_models || "";
  const rawModel = process.env.OPENROUTER_MODEL || process.env.openrouter_model || "";

  let models;

  if (isNonEmptyString(rawList)) {
    models = rawList
      .split(/[,\n]/)
      .map((m) => String(m || "").trim())
      .filter(Boolean);
  } else if (isNonEmptyString(rawModel)) {
    models = [rawModel.trim()];
  } else {
    models = ["openrouter/free"];
  }

  const seen = new Set();
  models = models.filter((m) => {
    const key = m.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  if (models.length === 0) {
    const err = new Error(
      "OpenRouter models are not configured. Set OPENROUTER_MODELS in server/.env.",
    );
    err.statusCode = 500;
    throw err;
  }

  for (const model of models) {
    if (model.startsWith("openrouter/")) continue;

    if (!model.endsWith(":free")) {
      const err = new Error(
        `Paid models are not allowed. Model must end with ':free' (got: ${model}).`,
      );
      err.statusCode = 500;
      throw err;
    }
  }

  return models;
}

function extractOpenRouterText(payload) {
  const choice = payload && payload.choices && payload.choices[0];
  const message = choice && choice.message;
  const content = message && message.content;

  if (typeof content === "string") return content.trim();

  if (Array.isArray(content)) {
    const text = content
      .map((part) => (part && part.type === "text" && typeof part.text === "string" ? part.text : ""))
      .join("")
      .trim();
    return text;
  }

  return "";
}

function getFetchTimeoutMs(envName, fallbackMs) {
  const raw = process.env[envName];
  if (!isNonEmptyString(raw)) return fallbackMs;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallbackMs;
  return Math.floor(parsed);
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const ms = typeof timeoutMs === "number" && Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 20_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...(options || {}), signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function openRouterGenerateText(prompt) {
  const apiKey = getOpenRouterApiKey();
  const models = getOpenRouterModels();
  const timeoutMs = getFetchTimeoutMs("OPENROUTER_TIMEOUT_MS", 25_000);

  const shouldFallback = (statusCode, message) => {
    if (statusCode === 429) return true;
    if (statusCode === 408) return true;
    if (statusCode === 502 || statusCode === 503 || statusCode === 504) return true;
    if (statusCode === 404 && typeof message === "string" && /no endpoints found/i.test(message)) {
      return true;
    }
    if (typeof message === "string" && /rate\s*limit|temporarily|overloaded|try again/i.test(message)) {
      return true;
    }
    return false;
  };

  let lastError = null;

  for (const model of models) {
    let res;
    try {
      res = await fetchWithTimeout(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
            "X-Title": "RepoSmart",
          },
          body: JSON.stringify({
            model,
            messages: [{ role: "user", content: prompt }],
            temperature: 0.2,
            max_tokens: 1024,
            provider: {
              max_price: { prompt: 0, completion: 0 },
              sort: "price",
            },
          }),
        },
        timeoutMs,
      );
    } catch (err) {
      const isAbort =
        err &&
        typeof err === "object" &&
        ((err.name && String(err.name) === "AbortError") || /aborted|abort/i.test(String(err.message || "")));

      const wrapped = new Error(
        isAbort ? `OpenRouter request timed out after ${timeoutMs}ms.` : (err && err.message ? err.message : "OpenRouter request failed."),
      );
      wrapped.statusCode = isAbort ? 504 : 502;
      lastError = wrapped;
      continue;
    }

    const json = await res.json().catch(() => null);

    if (!res.ok) {
      let message = `OpenRouter API request failed (${res.status})`;
      if (json && typeof json === "object" && json.error && typeof json.error === "object") {
        if (typeof json.error.message === "string" && json.error.message.trim().length > 0) {
          message = json.error.message;
        }

        if (
          json.error.metadata &&
          typeof json.error.metadata === "object" &&
          typeof json.error.metadata.raw === "string" &&
          json.error.metadata.raw.trim().length > 0
        ) {
          message = json.error.metadata.raw;
        }
      }

      const err = new Error(message);
      err.statusCode = res.status;
      lastError = err;

      if (shouldFallback(res.status, message)) {
        continue;
      }

      throw err;
    }

    const text = extractOpenRouterText(json);
    if (!isNonEmptyString(text)) {
      const err = new Error("OpenRouter returned an empty response.");
      err.statusCode = 502;
      lastError = err;
      continue;
    }

    return { model, text };
  }

  throw lastError || new Error("OpenRouter request failed.");
}

function getGitHubHeaders() {
  const { version } = getGitHubApiConfig();
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "RepoSmart",
    "X-GitHub-Api-Version": version,
  };

  const token = process.env.GITHUB_TOKEN;
  if (isNonEmptyString(token)) {
    headers.Authorization = `Bearer ${token.trim()}`;
  }

  return headers;
}

function isRelevantSourceFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return [".js", ".ts", ".py", ".sh", ".json", ".env"].includes(ext);
}

function normalizeRepoRelativePath(rootDir, absoluteFilePath) {
  const rel = path.relative(rootDir, absoluteFilePath);
  // Prefer forward slashes in API responses for portability.
  return rel.split(path.sep).join("/");
}

function looksBinary(buffer) {
  // Heuristic: treat NUL bytes as a strong binary indicator.
  if (!Buffer.isBuffer(buffer)) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 8000));
  return sample.includes(0);
}

/**
 * Download a GitHub repository zipball to disk.
 * Returns: { tempBase, zipPath }
 *
 * Required structure: downloadZip(url)
 */
async function downloadZip(zipUrl) {
  const tempBase = await fsp.mkdtemp(path.join(os.tmpdir(), "reposmart-zipscan-"));
  const zipPath = path.join(tempBase, "repo.zip");

  try {
    console.log(`[ZIPSCAN] Downloading ZIP: ${zipUrl}`);
    const res = await axios.get(zipUrl, {
      responseType: "stream",
      headers: getGitHubHeaders(),
      timeout: 60_000,
      maxRedirects: 5,
      validateStatus: () => true,
    });

    if (res.status < 200 || res.status >= 300) {
      const err = new Error(`Download failed (HTTP ${res.status}).`);
      err.statusCode = res.status;
      throw err;
    }

    await pipeline(res.data, fs.createWriteStream(zipPath));
    const stat = await fsp.stat(zipPath).catch(() => null);
    const zipBytes = stat && typeof stat.size === "number" ? stat.size : 0;
    console.log(`[ZIPSCAN] ZIP created: ${zipPath} (${zipBytes} bytes)`);
    return { tempBase, zipPath, zipBytes };
  } catch (err) {
    // Best-effort cleanup of temp directory if download fails.
    try {
      await fsp.rm(tempBase, { recursive: true, force: true });
    } catch {
      // ignore
    }

    const wrapped = new Error(
      err instanceof Error && err.message ? err.message : "Unable to download repository ZIP.",
    );
    wrapped.statusCode = err && typeof err.statusCode === "number" ? err.statusCode : 502;
    throw wrapped;
  }
}

/**
 * Extract a zip file into a new directory.
 * Returns the directory that contains repository contents.
 *
 * Required structure: extractZip(zipPath)
 */
async function extractZip(zipPath) {
  const destinationDir = path.join(path.dirname(zipPath), "extracted");
  await fsp.mkdir(destinationDir, { recursive: true });

  // Stream extraction (avoids loading the whole ZIP into memory).
  await fs
    .createReadStream(zipPath)
    .pipe(unzipper.Extract({ path: destinationDir }))
    .promise();

  // GitHub zipball usually contains a single root folder.
  const entries = await fsp.readdir(destinationDir, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory());
  if (dirs.length === 1) {
    return path.join(destinationDir, dirs[0].name);
  }

  return destinationDir;
}

/**
 * Load malware keywords from MongoDB, with a small in-memory cache.
 * Returns compiled matchers for substring and regex patterns.
 */
async function getMalwareKeywordsFromDB() {
  const now = Date.now();
  if (malwareKeywordCache.compiled && now - malwareKeywordCache.loadedAtMs < malwareKeywordCache.ttlMs) {
    return malwareKeywordCache.compiled;
  }

  const docs = await getMalwareKeywordDocsFromDB();

  const substringPatterns = [];
  const regexPatterns = [];

  for (const doc of Array.isArray(docs) ? docs : []) {
    if (!doc || typeof doc.pattern !== "string") continue;
    const pattern = doc.pattern.trim();
    if (!pattern) continue;

    const weight = safeNumber(doc.weight, 1);
    const category = typeof doc.category === "string" && doc.category.trim().length > 0 ? doc.category.trim() : "generic";
    const source = typeof doc.source === "string" && doc.source.trim().length > 0 ? doc.source.trim() : "custom";

    const matchMode = doc.matchMode === "regex" ? "regex" : "substring";
    if (matchMode === "substring") {
      substringPatterns.push({ pattern, lower: pattern.toLowerCase(), weight, category, matchMode, source });
      continue;
    }

    try {
      // Case-insensitive by default to catch common variants.
      regexPatterns.push({ pattern, regex: new RegExp(pattern, "i"), weight, category, matchMode, source });
    } catch {
      // Skip invalid regex entries rather than failing the entire scan.
    }
  }

  const compiled = {
    substrings: substringPatterns,
    regexes: regexPatterns,
  };

  malwareKeywordCache = {
    ...malwareKeywordCache,
    loadedAtMs: now,
    compiled,
  };

  return compiled;
}

/**
 * Load raw MalwareKeyword documents from MongoDB with the same cache window.
 * This is used by metadata scan (keywordMatchesCorpus).
 */
async function getMalwareKeywordDocsFromDB() {
  const now = Date.now();
  if (malwareKeywordCache.docs && now - malwareKeywordCache.loadedAtMs < malwareKeywordCache.ttlMs) {
    return malwareKeywordCache.docs;
  }

  let docs;
  try {
    docs = await MalwareKeyword.find({ enabled: true }).lean();
  } catch (err) {
    const wrapped = new Error(
      err instanceof Error && err.message ? err.message : "Unable to fetch malware keywords from database.",
    );
    wrapped.statusCode = 500;
    throw wrapped;
  }

  malwareKeywordCache = {
    ...malwareKeywordCache,
    loadedAtMs: now,
    docs,
    // compiled is still valid only if derived from same docs; force refresh next time.
    compiled: null,
  };

  return docs;
}

/**
 * Detect keyword matches for a file's content.
 * Returns an array of matched keyword strings.
 */
function detectMatches(fileContent, keywords) {
  if (!isNonEmptyString(fileContent)) return [];
  if (!keywords || typeof keywords !== "object") return [];

  const matched = [];
  const seen = new Set();
  const lower = fileContent.toLowerCase();

  const substrings = Array.isArray(keywords.substrings) ? keywords.substrings : [];
  for (const item of substrings) {
    if (!item || typeof item.lower !== "string" || typeof item.pattern !== "string") continue;
    if (item.lower && lower.includes(item.lower) && !seen.has(item.pattern)) {
      seen.add(item.pattern);
      matched.push(item);
    }
  }

  const regexes = Array.isArray(keywords.regexes) ? keywords.regexes : [];
  for (const item of regexes) {
    if (!item || !(item.regex instanceof RegExp) || typeof item.pattern !== "string") continue;
    try {
      if (item.regex.test(fileContent) && !seen.has(item.pattern)) {
        seen.add(item.pattern);
        matched.push(item);
      }
    } catch {
      // Ignore pathological regex runtime errors.
    }
  }

  return matched;
}

/**
 * Recursively scan directory files, limited to relevant extensions and size.
 * @param {string} directoryRoot
 * @param {{substrings: string[], regexes: Array<{pattern: string, regex: RegExp}>}} keywords
 */
async function scanFiles(directoryRoot, keywords) {
  const maxFileBytes = 2 * 1024 * 1024;

  let totalFilesScanned = 0;
  const suspiciousFiles = [];
  const globalMatches = new Map();

  async function walk(currentDir) {
    let entries;
    try {
      entries = await fsp.readdir(currentDir, { withFileTypes: true });
    } catch {
      // Directory unreadable; skip.
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (!isRelevantSourceFile(fullPath)) continue;

      let stat;
      try {
        stat = await fsp.stat(fullPath);
      } catch {
        continue;
      }

      if (!stat || typeof stat.size !== "number" || stat.size <= 0) continue;
      if (stat.size > maxFileBytes) continue;

      let buffer;
      try {
        buffer = await fsp.readFile(fullPath);
      } catch {
        // File read error; skip.
        continue;
      }

      if (looksBinary(buffer)) continue;

      let content;
      try {
        content = buffer.toString("utf8");
      } catch {
        continue;
      }

      totalFilesScanned += 1;
      const matchedItems = detectMatches(content, keywords);
      if (matchedItems.length > 0) {
        const matchedKeywords = matchedItems.map((m) => m.pattern);
        suspiciousFiles.push({
          filePath: normalizeRepoRelativePath(directoryRoot, fullPath),
          matchedKeywords,
        });

        for (const match of matchedItems) {
          if (!match || typeof match.pattern !== "string") continue;
          const prev = globalMatches.get(match.pattern);
          const next = {
            pattern: match.pattern,
            matchMode: match.matchMode || "substring",
            category: match.category || "generic",
            weight: safeNumber(match.weight, 1),
            source: match.source || "custom",
            hitCount: safeNumber(prev && prev.hitCount, 0) + 1,
          };
          globalMatches.set(match.pattern, next);
        }
      }
    }
  }

  await walk(directoryRoot);

  const matches = Array.from(globalMatches.values()).sort((a, b) => safeNumber(b.weight, 0) - safeNumber(a.weight, 0));
  const totalScore = matches.reduce((sum, m) => sum + safeNumber(m.weight, 0), 0);

  return { totalFilesScanned, suspiciousFiles, matches, totalScore };
}

function mergeMetadataAndZipMatches(metadataMatches, zipMatches) {
  const merged = new Map();

  for (const m of Array.isArray(metadataMatches) ? metadataMatches : []) {
    if (!m || typeof m.pattern !== "string") continue;
    merged.set(m.pattern, {
      pattern: m.pattern,
      matchMode: m.matchMode || "substring",
      category: m.category || "generic",
      weight: safeNumber(m.weight, 0),
      fields: Array.isArray(m.fields) ? Array.from(new Set(m.fields)) : [],
      source: m.source || "custom",
    });
  }

  for (const z of Array.isArray(zipMatches) ? zipMatches : []) {
    if (!z || typeof z.pattern !== "string") continue;
    const prev = merged.get(z.pattern);
    if (prev) {
      const fields = new Set(Array.isArray(prev.fields) ? prev.fields : []);
      fields.add("zip");
      merged.set(z.pattern, { ...prev, fields: Array.from(fields) });
    } else {
      merged.set(z.pattern, {
        pattern: z.pattern,
        matchMode: z.matchMode || "substring",
        category: z.category || "generic",
        weight: safeNumber(z.weight, 0),
        fields: ["zip"],
        source: z.source || "custom",
      });
    }
  }

  const list = Array.from(merged.values());
  list.sort((a, b) => safeNumber(b.weight, 0) - safeNumber(a.weight, 0));
  const totalScore = list.reduce((sum, m) => sum + safeNumber(m.weight, 0), 0);
  return { matches: list, totalScore };
}

async function githubRequestJson(path, query) {
  const url = buildGitHubApiUrl(path, query);
  const res = await fetchWithTimeout(
    url,
    {
      method: "GET",
      headers: getGitHubHeaders(),
    },
    getFetchTimeoutMs("GITHUB_FETCH_TIMEOUT_MS", 20_000),
  );

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // Ignore non-JSON responses.
  }

  if (!res.ok) {
    const message =
      json && typeof json === "object" && typeof json.message === "string"
        ? json.message
        : `GitHub API request failed (${res.status})`;

    const err = new Error(message);
    err.statusCode = res.status;
    err.github = { url, message };
    throw err;
  }

  return { data: json, headers: res.headers };
}

async function githubRequestText(path, query, accept) {
  const url = buildGitHubApiUrl(path, query);
  const headers = getGitHubHeaders();
  if (accept) headers.Accept = accept;

  const res = await fetchWithTimeout(
    url,
    {
      method: "GET",
      headers,
    },
    getFetchTimeoutMs("GITHUB_FETCH_TIMEOUT_MS", 20_000),
  );

  const text = await res.text();

  if (!res.ok) {
    let message = `GitHub API request failed (${res.status})`;
    try {
      const json = text ? JSON.parse(text) : null;
      if (json && typeof json.message === "string") message = json.message;
    } catch {
      // ignore
    }

    const err = new Error(message);
    err.statusCode = res.status;
    err.github = { url, message };
    throw err;
  }

  return { data: text, headers: res.headers };
}

function encodeGitHubPath(pathValue) {
  return String(pathValue || "")
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

async function fetchRepositoryFileText({ owner, repo, filePath }) {
  const encodedPath = encodeGitHubPath(filePath);
  if (!encodedPath) {
    throw badRequest("Invalid repository file path.");
  }

  const response = await githubRequestText(
    `/repos/${owner}/${repo}/contents/${encodedPath}`,
    undefined,
    "application/vnd.github.raw",
  );

  return typeof response.data === "string" ? response.data : "";
}

function parseLastPageFromLinkHeader(linkHeader) {
  if (!isNonEmptyString(linkHeader)) return null;

  const parts = linkHeader.split(",").map((part) => part.trim());
  const lastPart = parts.find((part) => part.includes('rel="last"'));
  if (!lastPart) return null;

  const urlMatch = lastPart.match(/<([^>]+)>/);
  if (!urlMatch) return null;

  try {
    const url = new URL(urlMatch[1]);
    const page = Number(url.searchParams.get("page"));
    return Number.isFinite(page) ? page : null;
  } catch {
    return null;
  }
}

function hasPathPrefix(pathsSet, prefix) {
  const normalized = prefix.endsWith("/") ? prefix : `${prefix}/`;
  for (const p of pathsSet) {
    if (p.startsWith(normalized)) return true;
  }
  return false;
}

function countByTopLevelFolder(filePaths) {
  const counts = new Map();
  for (const p of filePaths) {
    const parts = p.split("/").filter(Boolean);
    const key = parts.length > 1 ? parts[0] : "/";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Object.fromEntries(counts.entries());
}

function analyzeReadme(readmeText) {
  const text = isNonEmptyString(readmeText) ? readmeText : "";

  const wordCount = text.split(/\s+/).filter(Boolean).length;

  const hasInstall = /\b(install|installation|getting started|setup)\b/i.test(text);
  const hasUsage = /\b(usage|how to use|examples?)\b/i.test(text);
  const hasScreenshots = /\b(screenshot|demo|preview)\b/i.test(text) || /!\[[^\]]*\]\([^)]+\)/.test(text);
  const hasBadges = /\[!\[[^\]]+\]\([^)]+\)\]/.test(text);
  const hasContributing = /\b(contributing|contribution)\b/i.test(text);
  const hasLicenseSection = /\blicense\b/i.test(text);
  const hasEnv = /\b\.env\b|environment variables|config(uration)?/i.test(text);
  const hasApiDocs = /\bapi\b|openapi|swagger/i.test(text);

  const headings = Array.from(text.matchAll(/^#{1,6}\s+(.+)$/gm)).map((m) => m[1].trim());

  return {
    present: wordCount > 0,
    wordCount,
    headings,
    hasInstall,
    hasUsage,
    hasScreenshots,
    hasBadges,
    hasContributing,
    hasLicenseSection,
    hasEnv,
    hasApiDocs,
    isVeryShort: wordCount > 0 && wordCount < 80,
  };
}

function detectTooling(pathsSet) {
  const basenames = new Set();
  for (const p of pathsSet) {
    if (typeof p !== "string") continue;
    const normalized = p.replace(/\\/g, "/");
    const parts = normalized.split("/").filter(Boolean);
    if (parts.length === 0) continue;
    basenames.add(parts[parts.length - 1]);
  }

  const hasAny = (...names) =>
    names.some((name) => pathsSet.has(name) || basenames.has(name));

  const hasEslint =
    hasAny(
      ".eslintrc",
      ".eslintrc.js",
      ".eslintrc.cjs",
      ".eslintrc.json",
      ".eslintrc.yml",
      ".eslintrc.yaml",
      "eslint.config.js",
      "eslint.config.mjs",
      "eslint.config.cjs",
    );

  const hasPrettier =
    hasAny(
      ".prettierrc",
      ".prettierrc.js",
      ".prettierrc.cjs",
      ".prettierrc.json",
      ".prettierrc.yml",
      ".prettierrc.yaml",
      "prettier.config.js",
      "prettier.config.cjs",
      "prettier.config.mjs",
    );

  const hasEditorConfig = hasAny(".editorconfig");

  const hasGitHubActions = hasPathPrefix(pathsSet, ".github/workflows");
  const hasDependabot = pathsSet.has(".github/dependabot.yml") || pathsSet.has(".github/dependabot.yaml");

  const hasTestsDir =
    hasPathPrefix(pathsSet, "test") ||
    hasPathPrefix(pathsSet, "tests") ||
    hasPathPrefix(pathsSet, "__tests__") ||
    Array.from(pathsSet).some((p) => /(^|\/)__tests__(\/|$)/.test(p));

  const hasDocsDir = hasPathPrefix(pathsSet, "docs") || hasPathPrefix(pathsSet, "doc");

  const hasSrcDir = hasPathPrefix(pathsSet, "src") || hasPathPrefix(pathsSet, "app");

  const hasLockfile =
    hasAny(
      "package-lock.json",
      "yarn.lock",
      "pnpm-lock.yaml",
      "bun.lockb",
      "bun.lock",
    );

  const hasDocker = hasAny("Dockerfile", "docker-compose.yml", "docker-compose.yaml");

  const hasEnvExample =
    hasAny(".env.example", ".env.sample", ".env.template");

  const hasContributingFile =
    hasAny(
      "CONTRIBUTING.md",
      "CONTRIBUTION.md",
      ".github/CONTRIBUTING.md",
      ".github/CONTRIBUTION.md",
    );

  const hasCodeOfConduct =
    hasAny("CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md");

  const hasChangelog = hasAny("CHANGELOG.md", "CHANGES.md");

  const hasSecurityPolicy = hasAny("SECURITY.md", ".github/SECURITY.md");

  const hasIssueTemplates = hasPathPrefix(pathsSet, ".github/ISSUE_TEMPLATE");
  const hasPullRequestTemplate =
    pathsSet.has(".github/PULL_REQUEST_TEMPLATE.md") || hasPathPrefix(pathsSet, ".github/PULL_REQUEST_TEMPLATE");

  const hasGitIgnore = hasAny(".gitignore");

  const hasDeployConfig =
    hasAny("vercel.json", "netlify.toml", "firebase.json", "app.yaml", "render.yaml");

  return {
    hasEslint,
    hasPrettier,
    hasEditorConfig,
    hasGitHubActions,
    hasDependabot,
    hasTestsDir,
    hasDocsDir,
    hasSrcDir,
    hasLockfile,
    hasDocker,
    hasEnvExample,
    hasContributingFile,
    hasCodeOfConduct,
    hasChangelog,
    hasSecurityPolicy,
    hasIssueTemplates,
    hasPullRequestTemplate,
    hasGitIgnore,
    hasDeployConfig,
  };
}

function conventionalCommitRate(commits) {
  if (!Array.isArray(commits) || commits.length === 0) return 0;
  const re = /^(feat|fix|docs|chore|refactor|test|style|perf|ci|build|revert)(\([^)]+\))?:\s.+/i;

  let matches = 0;
  for (const c of commits) {
    const msg = c && c.commit && c.commit.message;
    if (typeof msg === "string" && re.test(msg.trim())) {
      matches += 1;
    }
  }

  return matches / commits.length;
}

function uniqueCommitDays(commits) {
  const days = new Set();
  for (const c of commits) {
    const date = c && c.commit && c.commit.author && c.commit.author.date;
    if (typeof date === "string") {
      days.add(date.slice(0, 10));
    }
  }
  return days.size;
}

function computeScore({
  repo,
  readme,
  tooling,
  tree,
  languages,
  gitStats,
}) {
  const breakdown = [];

  // Documentation (0-20)
  let documentation = 0;
  if (readme.present) documentation += 8;
  if (readme.hasInstall) documentation += 3;
  if (readme.hasUsage) documentation += 3;
  if (readme.hasScreenshots) documentation += 2;
  if (readme.hasBadges) documentation += 1;
  if (tooling.hasContributingFile || readme.hasContributing) documentation += 1;
  if (tooling.hasChangelog) documentation += 1;
  if (tooling.hasCodeOfConduct) documentation += 1;

  // Avoid giving full marks for a tiny README.
  if (readme.isVeryShort) documentation = Math.max(0, documentation - 2);

  documentation = clamp(documentation, 0, 20);
  breakdown.push({ key: "documentation", label: "Documentation & clarity", score: documentation, max: 20 });

  // Structure & organization (0-15)
  let structure = 0;
  if (tooling.hasSrcDir) structure += 5;
  if (tooling.hasDocsDir) structure += 2;
  if (tooling.hasGitIgnore) structure += 2;
  if (tooling.hasLockfile) structure += 2;
  if (tree && tree.fileCount >= 10) structure += 2;
  if (tree && tree.fileCount >= 50) structure += 2;

  structure = clamp(structure, 0, 15);
  breakdown.push({ key: "structure", label: "Project structure", score: structure, max: 15 });

  // Code quality & readability (0-25)
  let codeQuality = 0;
  if (tooling.hasEslint) codeQuality += 8;
  if (tooling.hasPrettier) codeQuality += 4;
  if (tooling.hasEditorConfig) codeQuality += 2;

  const languageCount = Object.keys(languages || {}).length;
  if (languageCount >= 1) codeQuality += 3;
  if (languageCount >= 3) codeQuality += 2;

  // Slight bonus if mostly TypeScript (signal for typed codebase)
  const languageBytes = Object.entries(languages || {});
  const totalBytes = languageBytes.reduce((acc, [, bytes]) => acc + safeNumber(bytes, 0), 0);
  const tsBytes = safeNumber(languages && languages.TypeScript, 0);
  if (totalBytes > 0 && tsBytes / totalBytes > 0.35) codeQuality += 3;

  // Penalize huge trees if truncated (less confidence)
  if (tree && tree.truncated) codeQuality = Math.max(0, codeQuality - 1);

  codeQuality = clamp(codeQuality, 0, 25);
  breakdown.push({ key: "codeQuality", label: "Code quality", score: codeQuality, max: 25 });

  // Testing & maintainability (0-20)
  let testing = 0;
  if (tooling.hasTestsDir) testing += 8;
  if (tooling.hasGitHubActions) testing += 7;
  if (tooling.hasDependabot) testing += 2;
  if (tooling.hasSecurityPolicy) testing += 1;
  if (readme.hasApiDocs) testing += 2;

  testing = clamp(testing, 0, 20);
  breakdown.push({ key: "testing", label: "Testing & maintainability", score: testing, max: 20 });

  // Git hygiene & consistency (0-10)
  let gitConsistency = 0;
  const commits90 = safeNumber(gitStats.commitsLast90Days, 0);
  const activeDays = safeNumber(gitStats.activeCommitDaysLast90Days, 0);
  const conventionalRate = safeNumber(gitStats.conventionalCommitRate, 0);
  const branches = safeNumber(gitStats.branches, 1);
  const prs = safeNumber(gitStats.pullRequests, 0);

  if (commits90 >= 5) gitConsistency += 3;
  if (commits90 >= 15) gitConsistency += 2;
  if (activeDays >= 5) gitConsistency += 2;
  if (activeDays >= 12) gitConsistency += 1;
  if (conventionalRate >= 0.4) gitConsistency += 1;
  if (branches >= 2) gitConsistency += 1;
  if (prs >= 1) gitConsistency += 0.5;

  gitConsistency = clamp(gitConsistency, 0, 10);
  breakdown.push({ key: "git", label: "Commit consistency", score: gitConsistency, max: 10 });

  // Real-world readiness (0-10)
  let readiness = 0;
  if (isNonEmptyString(repo.description) && repo.description.trim().length >= 20) readiness += 2;
  if (Array.isArray(repo.topics) && repo.topics.length >= 3) readiness += 2;
  if (tooling.hasDocker) readiness += 2;
  if (tooling.hasDeployConfig) readiness += 2;
  if (readme.hasEnv) readiness += 2;

  // Avoid overly penalizing brand new repos; but forks should not score high on originality.
  if (repo.fork) readiness = Math.max(0, readiness - 2);

  readiness = clamp(readiness, 0, 10);
  breakdown.push({ key: "readiness", label: "Real-world readiness", score: readiness, max: 10 });

  const total = breakdown.reduce((acc, item) => acc + item.score, 0);

  const level = total >= 80 ? "Advanced" : total >= 55 ? "Intermediate" : "Beginner";
  const badge = total >= 85 ? "Gold" : total >= 70 ? "Silver" : total >= 55 ? "Bronze" : "Starter";

  return {
    total: Math.round(total),
    level,
    badge,
    breakdown,
  };
}

function buildSummary({ score, readme, tooling, gitStats, repo }) {
  const strengths = [];
  const gaps = [];

  if (readme.present && !readme.isVeryShort) strengths.push("README is present and reasonably detailed");
  else gaps.push("README needs clearer setup/usage documentation");

  if (tooling.hasEslint || tooling.hasPrettier) strengths.push("has code quality tooling (lint/format) signals");
  else gaps.push("add linting/formatting to improve readability and consistency");

  if (tooling.hasTestsDir) strengths.push("includes a testing footprint");
  else gaps.push("add unit/integration tests to improve maintainability");

  if (tooling.hasGitHubActions) strengths.push("automates checks with CI workflows");
  else gaps.push("add GitHub Actions CI for lint/test on every push/PR");

  const commits90 = safeNumber(gitStats.commitsLast90Days, 0);
  if (commits90 >= 10) strengths.push("recent development activity is visible in commit history");
  else gaps.push("commit more consistently with smaller, meaningful changes");

  const lastPushDays = daysBetween(repo.pushed_at, new Date().toISOString());
  if (typeof lastPushDays === "number" && lastPushDays <= 30) strengths.push("recently updated");
  else gaps.push("refresh the project (recent commits) to show it’s maintained");

  const strengthText = strengths.slice(0, 2).join("; ");
  const gapText = gaps.slice(0, 2).join("; ");

  const headline = `Score ${score.total}/100 (${score.level}, ${score.badge}).`;
  const note = `Strengths: ${strengthText || "some good foundations are present"}.`;
  const next = `Needs work: ${gapText || "focus on polishing docs/tests/CI"}.`;

  return [headline, note, next].join(" ");
}

function buildRoadmap({ score, readme, tooling, gitStats, repo }) {
  const steps = [];

  if (!readme.present || readme.isVeryShort || !readme.hasInstall || !readme.hasUsage) {
    steps.push(
      "Improve README: add a 1-paragraph overview, setup/install steps, usage examples, and (if applicable) screenshots/demo links.",
    );
  }

  if (!tooling.hasGitIgnore) {
    steps.push("Add a `.gitignore` suited to your stack to avoid committing build artifacts and secrets.");
  }

  if (!tooling.hasEslint) {
    steps.push("Add linting (e.g., ESLint) and fix high-signal warnings to improve code consistency.");
  }

  if (!tooling.hasPrettier) {
    steps.push("Add a formatter (e.g., Prettier) and apply consistent formatting across the repo.");
  }

  if (!tooling.hasTestsDir) {
    steps.push(
      "Add tests: start with unit tests for core logic, then add at least one integration/e2e test for the main user flow.",
    );
  }

  if (!tooling.hasGitHubActions) {
    steps.push(
      "Add CI (GitHub Actions): run lint + tests on push and pull requests; fail the build when checks fail.",
    );
  }

  if (!tooling.hasDependabot) {
    steps.push("Add Dependabot to keep dependencies updated automatically.");
  }

  if (!tooling.hasEnvExample && readme.hasEnv) {
    steps.push("Add an `.env.example` that documents required environment variables (without secrets).");
  }

  if (!tooling.hasContributingFile) {
    steps.push("Add `CONTRIBUTING.md` with how to run, test, and propose changes.");
  }

  if (!tooling.hasSecurityPolicy) {
    steps.push("Add `SECURITY.md` explaining how to report vulnerabilities.");
  }

  const commits90 = safeNumber(gitStats.commitsLast90Days, 0);
  if (commits90 < 10) {
    steps.push(
      "Improve Git history: commit smaller, focused changes and use clear commit messages (consider Conventional Commits).");
  }

  if (repo.fork) {
    steps.push("If this is a fork, document what you changed and why; ideally link to upstream PRs or issues.");
  }

  // Ensure roadmap always has at least a few items.
  if (steps.length < 3) {
    steps.push("Add a small feature or refactor and document it to show iterative development.");
    steps.push("Open a pull request for a change (even in your own repo) to demonstrate PR workflow.");
  }

  // Personalize ordering: if score is already high, emphasize polish/community.
  if (score.total >= 85) {
    steps.unshift("Polish: add a short architecture section and a clear feature list in the README.");
  }

  // Deduplicate while preserving order.
  const seen = new Set();
  const unique = [];
  for (const step of steps) {
    const key = crypto.createHash("sha1").update(step).digest("hex");
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(step);
  }

  return unique.slice(0, 10);
}

async function fetchCountFromPagedEndpoint(path, query) {
  const { data, headers } = await githubRequestJson(path, query);
  const link = headers.get("link");
  const lastPage = parseLastPageFromLinkHeader(link);

  if (typeof lastPage === "number") {
    return { count: lastPage, sampled: true };
  }

  if (Array.isArray(data)) {
    return { count: data.length, sampled: true };
  }

  return { count: 0, sampled: true };
}

async function fetchRecentCommits(owner, repo, sinceIso) {
  const commits = [];
  let page = 1;
  const perPage = 100;
  const maxPages = 3;
  let capped = false;

  while (page <= maxPages) {
    const { data, headers } = await githubRequestJson(`/repos/${owner}/${repo}/commits`, {
      since: sinceIso,
      per_page: perPage,
      page,
    });

    if (!Array.isArray(data) || data.length === 0) break;

    commits.push(...data);

    const link = headers.get("link");
    const hasNext = isNonEmptyString(link) && link.includes('rel="next"');

    if (!hasNext) {
      capped = false;
      break;
    }

    if (page === maxPages) {
      capped = true;
      break;
    }

    page += 1;
  }

  return { commits, capped };
}

exports.analyzeRepository = async (req, res) => {
  try {
    const url = (req.body && (req.body.url || req.body.input)) || "";

    const { owner, repo } = parseGithubRepoInput(url);

    const cacheKey = buildAnalyzeCacheKey(owner, repo);
    const cached = await redisGetJson(cacheKey);
    if (cached && typeof cached === "object") {
      res.set("X-RepoSmart-Cache", "HIT");
      if (cached.input && typeof cached.input === "object") {
        cached.input = { ...cached.input, url };
      }
      return res.json(cached);
    }

    const repoMetaResp = await githubRequestJson(`/repos/${owner}/${repo}`);
    const repoMeta = repoMetaResp.data;

    const languagesResp = await githubRequestJson(`/repos/${owner}/${repo}/languages`);
    const languages = languagesResp.data || {};

    let readmeText = "";
    try {
      const readmeResp = await githubRequestText(
        `/repos/${owner}/${repo}/readme`,
        undefined,
        "application/vnd.github.raw",
      );
      readmeText = readmeResp.data;
    } catch {
      readmeText = "";
    }

    let treeInfo = {
      fileCount: 0,
      directoryCount: 0,
      truncated: false,
      topLevelCounts: {},
      paths: [],
    };

    try {
      const treeResp = await githubRequestJson(`/repos/${owner}/${repo}/git/trees/${repoMeta.default_branch}`, {
        recursive: 1,
      });

      const tree = treeResp.data;
      const items = tree && Array.isArray(tree.tree) ? tree.tree : [];

      const filePaths = items
        .filter((item) => item && item.type === "blob" && typeof item.path === "string")
        .map((item) => item.path);

      const dirCount = items.filter((item) => item && item.type === "tree").length;

      treeInfo = {
        fileCount: filePaths.length,
        directoryCount: dirCount,
        truncated: Boolean(tree && tree.truncated),
        topLevelCounts: countByTopLevelFolder(filePaths),
        paths: filePaths,
      };
    } catch {
      // Tree API occasionally fails for very large repos; keep analysis going.
    }

    const pathsSet = new Set(treeInfo.paths);
    const tooling = detectTooling(pathsSet);

    const since = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

    let recentCommits = [];
    let commitsCapped = false;
    try {
      const commitsResp = await fetchRecentCommits(owner, repo, since);
      recentCommits = commitsResp.commits;
      commitsCapped = commitsResp.capped;
    } catch (err) {
      // Empty repos can return 409 "Git Repository is empty" for commit endpoints.
      if (err && typeof err.statusCode === "number" && err.statusCode === 409) {
        recentCommits = [];
        commitsCapped = false;
      } else {
        throw err;
      }
    }

    const safeCount = async (path, query) => {
      try {
        const resp = await fetchCountFromPagedEndpoint(path, query);
        return resp.count;
      } catch (err) {
        if (err && typeof err.statusCode === "number" && err.statusCode === 409) {
          return 0;
        }
        throw err;
      }
    };

    const branches = await safeCount(`/repos/${owner}/${repo}/branches`, { per_page: 1 });
    const pullRequests = await safeCount(`/repos/${owner}/${repo}/pulls`, { state: "all", per_page: 1 });
    const contributors = await safeCount(`/repos/${owner}/${repo}/contributors`, { per_page: 1, anon: 1 });
    const releases = await safeCount(`/repos/${owner}/${repo}/releases`, { per_page: 1 });

    const gitStats = {
      commitsLast90Days: recentCommits.length,
      commitsLast90DaysCapped: commitsCapped,
      activeCommitDaysLast90Days: uniqueCommitDays(recentCommits),
      conventionalCommitRate: conventionalCommitRate(recentCommits),
      branches,
      pullRequests,
      contributors,
      releases,
    };

    const readme = analyzeReadme(readmeText);
    const licenseDetection = await detectRepositoryLicense({
      owner,
      repo,
      repoMeta,
      treeInfo,
      fetchFileText: fetchRepositoryFileText,
    });

    const score = computeScore({
      repo: repoMeta,
      readme,
      tooling,
      tree: treeInfo,
      languages,
      gitStats,
    });

    const trustReport = generateTrustReport({
      baseScore: score,
      licenseDetection,
      malwareRisk: { normalizedRiskScore: 0 },
      readmeSnapshot: readme,
      gitSnapshot: gitStats,
    });

    const summary = buildSummary({ score, readme, tooling, gitStats, repo: repoMeta });
    const roadmap = buildRoadmap({ score, readme, tooling, gitStats, repo: repoMeta });

    // Convert language bytes to percentage breakdown (top 5).
    const entries = Object.entries(languages);
    const total = entries.reduce((acc, [, bytes]) => acc + safeNumber(bytes, 0), 0);
    const languagesTop = entries
      .map(([name, bytes]) => ({
        name,
        bytes: safeNumber(bytes, 0),
      }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 5)
      .map((item) => ({
        ...item,
        percent: total > 0 ? Math.round((item.bytes / total) * 100) : 0,
      }));

    const payload = {
      input: { owner, repo, url },
      repo: {
        fullName: repoMeta.full_name,
        htmlUrl: repoMeta.html_url,
        description: repoMeta.description,
        defaultBranch: repoMeta.default_branch,
        isFork: Boolean(repoMeta.fork),
        visibility: repoMeta.visibility,
        stars: safeNumber(repoMeta.stargazers_count, 0),
        forks: safeNumber(repoMeta.forks_count, 0),
        watchers: safeNumber(repoMeta.watchers_count, 0),
        openIssues: safeNumber(repoMeta.open_issues_count, 0),
        license: licenseDetection.license,
        topics: Array.isArray(repoMeta.topics) ? repoMeta.topics : [],
        createdAt: repoMeta.created_at,
        updatedAt: repoMeta.updated_at,
        pushedAt: repoMeta.pushed_at,
        sizeKb: safeNumber(repoMeta.size, 0),
      },
      licenseDetection,
      snapshot: {
        files: {
          fileCount: treeInfo.fileCount,
          directoryCount: treeInfo.directoryCount,
          truncated: treeInfo.truncated,
          topLevelCounts: treeInfo.topLevelCounts,
        },
        languagesTop,
        readme: {
          present: readme.present,
          wordCount: readme.wordCount,
          hasInstall: readme.hasInstall,
          hasUsage: readme.hasUsage,
          hasScreenshots: readme.hasScreenshots,
          hasBadges: readme.hasBadges,
        },
        tooling,
        git: gitStats,
      },
      score,
      trustReport,
      summary,
      roadmap,

      // Cache metadata is intentionally omitted from response.
    };

    // Best-effort cache write.
    await redisSetJson(cacheKey, payload, getAnalyzeCacheTtlSeconds());

    res.set("X-RepoSmart-Cache", "MISS");
    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;

    // Friendly GitHub messages.
    let message = err instanceof Error ? err.message : "Unable to analyze repository.";

    if (status === 404) {
      message = "Repository not found (or it may be private).";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  }
};

exports.aiScanRepository = async (req, res) => {
  try {
    const url = (req.body && (req.body.url || req.body.input)) || "";

    const { owner, repo } = parseGithubRepoInput(url);

    const modelsSignature = getOpenRouterModels().join(",");
    const cacheKey = buildAiScanCacheKey(owner, repo, modelsSignature);
    const cached = await redisGetJson(cacheKey);
    if (cached && typeof cached === "object") {
      res.set("X-RepoSmart-Cache", "HIT");
      if (cached.input && typeof cached.input === "object") {
        cached.input = { ...cached.input, url };
      }
      return res.json(cached);
    }

    // If the repo was recently analyzed, reuse that cached GitHub metadata to
    // avoid redundant GitHub API calls for AI scans.
    const analyzeCacheKey = buildAnalyzeCacheKey(owner, repo);
    const analyzeCached = await redisGetJson(analyzeCacheKey);
    if (
      analyzeCached &&
      typeof analyzeCached === "object" &&
      analyzeCached.repo &&
      typeof analyzeCached.repo === "object" &&
      analyzeCached.snapshot &&
      typeof analyzeCached.snapshot === "object"
    ) {
      const snapshot = analyzeCached.snapshot;
      const licenseDetection =
        analyzeCached.licenseDetection && typeof analyzeCached.licenseDetection === "object"
          ? analyzeCached.licenseDetection
          : {
              license: analyzeCached.repo.license || "MISSING",
              confidence: analyzeCached.repo.license ? "high" : "low",
              source: analyzeCached.repo.license ? "github_api" : "not_found",
              ...(analyzeCached.repo.license ? null : { riskImpact: "HIGH" }),
            };

      const pipelineCache = await redisGetJson(buildMalwarePipelineCacheKey(owner, repo));
      const malwareSummary =
        pipelineCache && pipelineCache.malwareExplanation && typeof pipelineCache.malwareExplanation.summary === "string"
          ? pipelineCache.malwareExplanation.summary
          : "Malware pipeline not executed yet.";
      const keyCategories =
        pipelineCache && Array.isArray(pipelineCache.matches)
          ? Array.from(
              new Set(
                pipelineCache.matches
                  .map((m) => (m && typeof m.category === "string" ? m.category : null))
                  .filter(Boolean),
              ),
            ).slice(0, 6)
          : [];
      const malwareRiskLevel =
        pipelineCache && typeof pipelineCache.riskLevel === "string" ? pipelineCache.riskLevel : "UNKNOWN";

      const trustReport =
        analyzeCached.trustReport && typeof analyzeCached.trustReport === "object"
          ? analyzeCached.trustReport
          : generateTrustReport({
              baseScore: analyzeCached.score,
              licenseDetection,
              malwareRisk: { normalizedRiskScore: 0 },
              readmeSnapshot: snapshot.readme,
              gitSnapshot: snapshot.git,
            });

      const metadata = {
        input: { owner, repo, url },
        repo: { ...analyzeCached.repo, license: licenseDetection.license },
        license: licenseDetection,
        trustReport,
        malwareSummary,
        keyCategories,
        riskLevel: malwareRiskLevel,
        snapshot: {
          files: snapshot.files,
          languagesTop: snapshot.languagesTop,
          readme: snapshot.readme,
          tooling: snapshot.tooling,
        },
      };

      const prompt =
        "You are RepoSmart, an assistant that evaluates GitHub repositories using metadata only. " +
        "Given the JSON metadata below, produce:\n" +
        "1) A 2-3 sentence overview.\n" +
        "2) Strengths (3-6 bullet points).\n" +
        "3) Gaps/risks (3-6 bullet points).\n" +
        "4) A prioritized action plan (5 items, concrete, repo-agnostic).\n" +
        "Keep the response plain text (no markdown headings).\n\n" +
        `METADATA_JSON:\n${JSON.stringify(metadata, null, 2)}`;

      const ai = await openRouterGenerateText(prompt);
      const aiParsed = tryParseJsonObject(ai.text);
      const aiInsights = generateAIInsights({
        metadata,
        aiParsed,
        trustReport,
      });

      const payload = {
        ...metadata,
        ai: {
          model: ai.model,
          output: ai.text,
          parsed: aiParsed,
        },
        aiInsights,
      };

      await redisSetJson(cacheKey, payload, getAiScanCacheTtlSeconds());

      res.set("X-RepoSmart-Cache", "MISS");
      return res.json(payload);
    }

    const repoMetaResp = await githubRequestJson(`/repos/${owner}/${repo}`);
    const repoMeta = repoMetaResp.data;

    const languagesResp = await githubRequestJson(`/repos/${owner}/${repo}/languages`);
    const languages = languagesResp.data || {};

    let readmeText = "";
    try {
      const readmeResp = await githubRequestText(
        `/repos/${owner}/${repo}/readme`,
        undefined,
        "application/vnd.github.raw",
      );
      readmeText = readmeResp.data;
    } catch {
      readmeText = "";
    }

    let treeInfo = {
      fileCount: 0,
      directoryCount: 0,
      truncated: false,
      topLevelCounts: {},
      paths: [],
    };

    try {
      const treeResp = await githubRequestJson(`/repos/${owner}/${repo}/git/trees/${repoMeta.default_branch}`, {
        recursive: 1,
      });

      const tree = treeResp.data;
      const items = tree && Array.isArray(tree.tree) ? tree.tree : [];

      const filePaths = items
        .filter((item) => item && item.type === "blob" && typeof item.path === "string")
        .map((item) => item.path);

      const dirCount = items.filter((item) => item && item.type === "tree").length;

      treeInfo = {
        fileCount: filePaths.length,
        directoryCount: dirCount,
        truncated: Boolean(tree && tree.truncated),
        topLevelCounts: countByTopLevelFolder(filePaths),
        paths: filePaths,
      };
    } catch {
      // keep going
    }

    const pathsSet = new Set(treeInfo.paths);
    const tooling = detectTooling(pathsSet);
    const readme = analyzeReadme(readmeText);
    const licenseDetection = await detectRepositoryLicense({
      owner,
      repo,
      repoMeta,
      treeInfo,
      fetchFileText: fetchRepositoryFileText,
    });

    const pipelineCache = await redisGetJson(buildMalwarePipelineCacheKey(owner, repo));
    const malwareSummary =
      pipelineCache && pipelineCache.malwareExplanation && typeof pipelineCache.malwareExplanation.summary === "string"
        ? pipelineCache.malwareExplanation.summary
        : "Malware pipeline not executed yet.";
    const keyCategories =
      pipelineCache && Array.isArray(pipelineCache.matches)
        ? Array.from(
            new Set(
              pipelineCache.matches
                .map((m) => (m && typeof m.category === "string" ? m.category : null))
                .filter(Boolean),
            ),
          ).slice(0, 6)
        : [];
    const malwareRiskLevel =
      pipelineCache && typeof pipelineCache.riskLevel === "string" ? pipelineCache.riskLevel : "UNKNOWN";

    const trustReport = generateTrustReport({
      baseScore: null,
      licenseDetection,
      malwareRisk: {
        normalizedRiskScore:
          pipelineCache && typeof pipelineCache.normalizedRiskScore === "number" ? pipelineCache.normalizedRiskScore : 0,
      },
      readmeSnapshot: readme,
      gitSnapshot: null,
    });

    // Language percentages (top 5)
    const entries = Object.entries(languages);
    const totalBytes = entries.reduce((acc, [, bytes]) => acc + safeNumber(bytes, 0), 0);
    const languagesTop = entries
      .map(([name, bytes]) => ({ name, bytes: safeNumber(bytes, 0) }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 5)
      .map((item) => ({
        ...item,
        percent: totalBytes > 0 ? Math.round((item.bytes / totalBytes) * 100) : 0,
      }));

    const metadata = {
      input: { owner, repo, url },
      repo: {
        fullName: repoMeta.full_name,
        htmlUrl: repoMeta.html_url,
        description: repoMeta.description,
        defaultBranch: repoMeta.default_branch,
        isFork: Boolean(repoMeta.fork),
        visibility: repoMeta.visibility,
        stars: safeNumber(repoMeta.stargazers_count, 0),
        forks: safeNumber(repoMeta.forks_count, 0),
        watchers: safeNumber(repoMeta.watchers_count, 0),
        openIssues: safeNumber(repoMeta.open_issues_count, 0),
        license: licenseDetection.license,
        topics: Array.isArray(repoMeta.topics) ? repoMeta.topics : [],
        createdAt: repoMeta.created_at,
        updatedAt: repoMeta.updated_at,
        pushedAt: repoMeta.pushed_at,
        sizeKb: safeNumber(repoMeta.size, 0),
      },
      license: licenseDetection,
      trustReport,
      malwareSummary,
      keyCategories,
      riskLevel: malwareRiskLevel,
      snapshot: {
        files: {
          fileCount: treeInfo.fileCount,
          directoryCount: treeInfo.directoryCount,
          truncated: treeInfo.truncated,
          topLevelCounts: treeInfo.topLevelCounts,
        },
        languagesTop,
        readme: {
          present: readme.present,
          wordCount: readme.wordCount,
          hasInstall: readme.hasInstall,
          hasUsage: readme.hasUsage,
          hasScreenshots: readme.hasScreenshots,
          hasBadges: readme.hasBadges,
        },
        tooling,
      },
    };

    const prompt =
      "You are RepoSmart, an assistant that evaluates GitHub repositories using metadata only. " +
      "Given the JSON metadata below, produce:\n" +
      "1) A 2-3 sentence overview.\n" +
      "2) Strengths (3-6 bullet points).\n" +
      "3) Gaps/risks (3-6 bullet points).\n" +
      "4) A prioritized action plan (5 items, concrete, repo-agnostic).\n" +
      "Keep the response plain text (no markdown headings).\n\n" +
      `METADATA_JSON:\n${JSON.stringify(metadata, null, 2)}`;

    const ai = await openRouterGenerateText(prompt);
    const aiParsed = tryParseJsonObject(ai.text);
    const aiInsights = generateAIInsights({
      metadata,
      aiParsed,
      trustReport,
    });

    const payload = {
      ...metadata,
      ai: {
        model: ai.model,
        output: ai.text,
        parsed: aiParsed,
      },
      aiInsights,
    };

    await redisSetJson(cacheKey, payload, getAiScanCacheTtlSeconds());

    res.set("X-RepoSmart-Cache", "MISS");
    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;

    let message = err instanceof Error ? err.message : "Unable to scan repository.";

    if (status === 404) {
      message = "Repository not found (or it may be private).";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  }
};

exports.malwareCheckRepository = async (req, res) => {
  try {
    const url = (req.body && (req.body.url || req.body.input)) || "";
    const { owner, repo } = parseGithubRepoInput(url);

    const cacheKey = buildMalwareScanCacheKey(owner, repo);
    const cached = await redisGetJson(cacheKey);
    if (cached && typeof cached === "object") {
      res.set("X-RepoSmart-Cache", "HIT");
      if (cached.input && typeof cached.input === "object") {
        cached.input = { ...cached.input, url };
      }

      // Always return a deterministic verdict.
      if (!cached.verdict || typeof cached.verdict !== "object") {
        const cachedScore =
          cached.patternMatch && typeof cached.patternMatch === "object" ? cached.patternMatch.totalScore : 0;
        const cachedMatches =
          cached.patternMatch && typeof cached.patternMatch === "object" ? cached.patternMatch.matches : [];
        const cachedRepo = cached.repo && typeof cached.repo === "object" ? cached.repo : {};
        const cachedAi = cached.ai && typeof cached.ai === "object" ? cached.ai : null;
        const cachedFilePathsText = cached.filePaths || (cached.snapshot && cached.snapshot.filePaths) || "";

        cached.verdict = computeMalwareVerdict({
          totalScore: safeNumber(cachedScore, 0),
          matches: Array.isArray(cachedMatches) ? cachedMatches : [],
          repoMeta: {
            topics: Array.isArray(cachedRepo.topics) ? cachedRepo.topics : [],
            description: typeof cachedRepo.description === "string" ? cachedRepo.description : "",
          },
          readmeText: "",
          filePathsText: typeof cachedFilePathsText === "string" ? cachedFilePathsText : "",
          aiParsed: cachedAi && cachedAi.parsed ? cachedAi.parsed : null,
        });

        await redisSetJson(cacheKey, cached, getMalwareScanCacheTtlSeconds());
      }

      return res.json(cached);
    }

    const repoMetaResp = await githubRequestJson(`/repos/${owner}/${repo}`);
    const repoMeta = repoMetaResp.data;

    const languagesResp = await githubRequestJson(`/repos/${owner}/${repo}/languages`);
    const languages = languagesResp.data || {};

    let readmeText = "";
    try {
      const readmeResp = await githubRequestText(
        `/repos/${owner}/${repo}/readme`,
        undefined,
        "application/vnd.github.raw",
      );
      readmeText = readmeResp.data;
    } catch {
      readmeText = "";
    }

    let treeInfo = {
      fileCount: 0,
      directoryCount: 0,
      truncated: false,
      topLevelCounts: {},
      paths: [],
    };

    try {
      const treeResp = await githubRequestJson(`/repos/${owner}/${repo}/git/trees/${repoMeta.default_branch}`, {
        recursive: 1,
      });

      const tree = treeResp.data;
      const items = tree && Array.isArray(tree.tree) ? tree.tree : [];

      const filePaths = items
        .filter((item) => item && item.type === "blob" && typeof item.path === "string")
        .map((item) => item.path);

      const dirCount = items.filter((item) => item && item.type === "tree").length;

      treeInfo = {
        fileCount: filePaths.length,
        directoryCount: dirCount,
        truncated: Boolean(tree && tree.truncated),
        topLevelCounts: countByTopLevelFolder(filePaths),
        paths: filePaths,
      };
    } catch {
      // keep going
    }

    const corpusByField = buildMetadataCorpus({ repoMeta, languages, readmeText, treeInfo });

    const keywords = await MalwareKeyword.find({ enabled: true }).lean();

    const matches = [];
    let totalScore = 0;

    for (const keyword of keywords) {
      const result = keywordMatchesCorpus(keyword, corpusByField);
      if (!result.matched) continue;

      const weight = safeNumber(keyword.weight, 0);
      totalScore += weight;
      matches.push({
        pattern: keyword.pattern,
        matchMode: keyword.matchMode || "substring",
        category: keyword.category || "generic",
        weight,
        fields: result.fields,
        source: keyword.source || "custom",
      });
    }

    matches.sort((a, b) => b.weight - a.weight);

    const metadata = {
      input: { owner, repo, url },
      repo: {
        fullName: repoMeta.full_name,
        htmlUrl: repoMeta.html_url,
        description: repoMeta.description,
        defaultBranch: repoMeta.default_branch,
        isFork: Boolean(repoMeta.fork),
        visibility: repoMeta.visibility,
        stars: safeNumber(repoMeta.stargazers_count, 0),
        forks: safeNumber(repoMeta.forks_count, 0),
        watchers: safeNumber(repoMeta.watchers_count, 0),
        openIssues: safeNumber(repoMeta.open_issues_count, 0),
        license: repoMeta.license ? repoMeta.license.spdx_id : null,
        topics: Array.isArray(repoMeta.topics) ? repoMeta.topics : [],
        createdAt: repoMeta.created_at,
        updatedAt: repoMeta.updated_at,
        pushedAt: repoMeta.pushed_at,
        sizeKb: safeNumber(repoMeta.size, 0),
      },
      snapshot: {
        files: {
          fileCount: treeInfo.fileCount,
          directoryCount: treeInfo.directoryCount,
          truncated: treeInfo.truncated,
          topLevelCounts: treeInfo.topLevelCounts,
        },
        languages: Object.keys(languages),
        readme: {
          present: isNonEmptyString(readmeText),
          wordCount: isNonEmptyString(readmeText) ? readmeText.split(/\s+/).filter(Boolean).length : 0,
        },
      },
      keywordModel: {
        enabledCount: keywords.length,
      },
    };

    const licenseDetection = await detectRepositoryLicense({
      owner,
      repo,
      repoMeta,
      treeInfo,
      fetchFileText: fetchRepositoryFileText,
    });

    let ai = null;
    try {
      const aiPrompt =
        "You are RepoSmart Malware Detector. You only have GitHub metadata and keyword matches; you do NOT have code content. " +
        "Decide if the repository is likely malicious. Output STRICT JSON ONLY with fields: " +
        "malicious (boolean), confidence (number 0..1), reasoning (string), indicators (string[]). " +
        "Be conservative: if evidence is weak, set malicious=false and lower confidence.\n\n" +
        `TOTAL_PATTERN_SCORE: ${totalScore}\n` +
        `TOP_MATCHES_JSON: ${JSON.stringify(matches.slice(0, 25), null, 2)}\n` +
        `METADATA_JSON: ${JSON.stringify(metadata, null, 2)}`;

      const generated = await openRouterGenerateText(aiPrompt);
      ai = {
        model: generated.model,
        output: generated.text,
        parsed: tryParseJsonObject(generated.text),
      };
    } catch {
      ai = null;
    }

    const verdict = computeMalwareVerdict({
      totalScore,
      matches,
      repoMeta,
      readmeText,
      filePathsText: corpusByField.filePaths,
      aiParsed: ai && ai.parsed ? ai.parsed : null,
    });
    const contextAdjusted = applyContextAwareRiskAdjustments({
      score: totalScore,
      matches,
      readmeText,
    });
    const risk = buildMalwareRiskMetrics(contextAdjusted.adjustedScore);
    const malwareExplanation = generateMalwareExplanation({
      score: contextAdjusted.adjustedScore,
      matchCount: matches.length,
      matches,
      verdict: verdict && verdict.level ? verdict.level : "SAFE",
    });
    const trustReport = generateTrustReport({
      baseScore: null,
      licenseDetection,
      malwareRisk: risk,
      readmeSnapshot: {
        present: isNonEmptyString(readmeText),
        hasInstall: /\b(install|installation|getting started|setup)\b/i.test(readmeText || ""),
        hasUsage: /\b(usage|how to use|examples?)\b/i.test(readmeText || ""),
      },
      gitSnapshot: null,
    });

    const payload = {
      ...metadata,
      licenseDetection,
      verdict,
      ...risk,
      contextAdjustments: contextAdjusted.adjustments,
      malwareExplanation,
      trustReport,
      patternMatch: {
        totalScore: risk.totalRiskScore,
        matches: matches.slice(0, 100),
      },
      ai,
    };

    await redisSetJson(cacheKey, payload, getMalwareScanCacheTtlSeconds());

    res.set("X-RepoSmart-Cache", "MISS");
    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;

    let message = err instanceof Error ? err.message : "Unable to run malware check.";

    if (status === 404) {
      message = "Repository not found (or it may be private).";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  }
};

/**
 * Malware detection by downloading the repository ZIP and scanning file contents.
 * Input: { url: string } (or { input: string } / { repoUrl: string })
 * Output:
 * {
 *   totalFilesScanned: number,
 *   suspiciousFiles: [{ filePath: string, matchedKeywords: string[] }]
 * }
 */
exports.malwareZipScanRepository = async (req, res) => {
  let tempBase;
  let zipPath;
  let zipBytes;

  try {
    const url = (req.body && (req.body.url || req.body.repoUrl || req.body.input)) || "";
    const debug =
      Boolean(req.query && (req.query.debug === "1" || req.query.debug === "true")) ||
      Boolean(req.body && req.body.debug);

    const { owner, repo } = parseGithubRepoInput(url);
    console.log(`[ZIPSCAN] Starting scan for ${owner}/${repo}`);

    const zipUrl = `https://api.github.com/repos/${owner}/${repo}/zipball`;

    const downloaded = await downloadZip(zipUrl);
    tempBase = downloaded.tempBase;
    zipPath = downloaded.zipPath;
    zipBytes = safeNumber(downloaded.zipBytes, 0);

    const stage = { zipDownloaded: true, zipDeleted: false, zipDeleteError: null, extracted: false };

    const extractedRoot = await extractZip(zipPath);
    stage.extracted = true;
    console.log(`[ZIPSCAN] Extracted to: ${extractedRoot}`);

    // Requirement: delete ZIP after extraction.
    try {
      await fsp.unlink(zipPath);
      stage.zipDeleted = true;
      console.log(`[ZIPSCAN] ZIP deleted after extraction: ${zipPath}`);
    } catch (unlinkErr) {
      stage.zipDeleteError = unlinkErr instanceof Error ? unlinkErr.message : "Unable to delete ZIP.";
      console.warn(`[ZIPSCAN] ZIP delete failed: ${zipPath} (${stage.zipDeleteError})`);
    }

    const keywords = await getMalwareKeywordsFromDB();
    const result = await scanFiles(extractedRoot, keywords);

    // Pass score + top matches + suspicious files summary to AI.
    let ai = null;
    try {
      const topMatches = Array.isArray(result.matches) ? result.matches.slice(0, 50) : [];
      const topSuspiciousFiles = Array.isArray(result.suspiciousFiles)
        ? result.suspiciousFiles.slice(0, 50)
        : [];

      const aiPrompt =
        "You are RepoSmart Malware Detector. You are analyzing a GitHub repository by scanning extracted source files for malware keywords. " +
        "Given the score and matched keywords below, decide if the repository is likely malicious. Output STRICT JSON ONLY with fields: " +
        "malicious (boolean), confidence (number 0..1), reasoning (string), indicators (string[]). " +
        "Be conservative: if evidence is weak, set malicious=false and lower confidence.\n\n" +
        `REPO_URL: ${url}\n` +
        `TOTAL_FILES_SCANNED: ${safeNumber(result.totalFilesScanned, 0)}\n` +
        `SUSPICIOUS_FILE_COUNT: ${Array.isArray(result.suspiciousFiles) ? result.suspiciousFiles.length : 0}\n` +
        `TOTAL_PATTERN_SCORE: ${Math.round(safeNumber(result.totalScore, 0) * 100) / 100}\n` +
        `TOP_MATCHES_JSON: ${JSON.stringify(topMatches, null, 2)}\n` +
        `TOP_SUSPICIOUS_FILES_JSON: ${JSON.stringify(topSuspiciousFiles, null, 2)}`;

      const generated = await openRouterGenerateText(aiPrompt);
      ai = {
        model: generated.model,
        output: generated.text,
        parsed: tryParseJsonObject(generated.text),
      };
    } catch {
      ai = null;
    }

    const response = {
      input: { owner, repo, url },
      repo: {
        fullName: `${owner}/${repo}`,
        htmlUrl: `https://github.com/${owner}/${repo}`,
      },
      totalFilesScanned: result.totalFilesScanned,
      suspiciousFiles: result.suspiciousFiles,
      ...buildMalwareRiskMetrics(result.totalScore),
      patternMatch: {
        totalScore: Math.round(safeNumber(result.totalScore, 0) * 100) / 100,
        matches: Array.isArray(result.matches) ? result.matches.slice(0, 100) : [],
      },
      ai,
    };

    if (debug) {
      response.debug = {
        zipCreated: true,
        zipBytes: safeNumber(zipBytes, 0),
        tempDir: typeof tempBase === "string" ? path.basename(tempBase) : null,
        stage,
      };
    }

    res.json(response);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;
    let message = err instanceof Error ? err.message : "Unable to scan repository ZIP.";

    console.error(`[ZIPSCAN] Failed: ${message}`);

    if (status === 404) message = "Repository not found (or it may be private).";
    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  } finally {
    // Requirement: delete extracted folder after scanning (also on failure).
    try {
      if (typeof tempBase === "string" && tempBase.trim().length > 0) {
        await fsp.rm(tempBase, { recursive: true, force: true });
        console.log(`[ZIPSCAN] Temp directory cleaned up: ${tempBase}`);
      }
    } catch {
      // ignore
    }
  }
};

/**
 * Combined malware scan: metadata keyword scan + ZIP content scan.
 * Returns a single verdict/AI output based on merged evidence.
 */
exports.malwareCombinedScanRepository = async (req, res) => {
  // ZIP scan uses a temp directory. Always cleaned up in finally.
  let tempBase;
  let zipPath;
  let zipBytes;

  try {
    const url = (req.body && (req.body.url || req.body.repoUrl || req.body.input)) || "";
    const { owner, repo } = parseGithubRepoInput(url);

    // ----- Metadata scan (existing behavior from malwareCheckRepository) -----
    const repoMetaResp = await githubRequestJson(`/repos/${owner}/${repo}`);
    const repoMeta = repoMetaResp.data;

    const languagesResp = await githubRequestJson(`/repos/${owner}/${repo}/languages`);
    const languages = languagesResp.data || {};

    let readmeText = "";
    try {
      const readmeResp = await githubRequestText(
        `/repos/${owner}/${repo}/readme`,
        undefined,
        "application/vnd.github.raw",
      );
      readmeText = readmeResp.data;
    } catch {
      readmeText = "";
    }

    let treeInfo = {
      fileCount: 0,
      directoryCount: 0,
      truncated: false,
      topLevelCounts: {},
      paths: [],
    };

    try {
      const treeResp = await githubRequestJson(`/repos/${owner}/${repo}/git/trees/${repoMeta.default_branch}`, {
        recursive: 1,
      });

      const tree = treeResp.data;
      const items = tree && Array.isArray(tree.tree) ? tree.tree : [];

      const filePaths = items
        .filter((item) => item && item.type === "blob" && typeof item.path === "string")
        .map((item) => item.path);

      const dirCount = items.filter((item) => item && item.type === "tree").length;

      treeInfo = {
        fileCount: filePaths.length,
        directoryCount: dirCount,
        truncated: Boolean(tree && tree.truncated),
        topLevelCounts: countByTopLevelFolder(filePaths),
        paths: filePaths,
      };
    } catch {
      // keep going
    }

    const corpusByField = buildMetadataCorpus({ repoMeta, languages, readmeText, treeInfo });

    const keywordDocs = await getMalwareKeywordDocsFromDB();
    const metadataMatches = [];
    let metadataScore = 0;

    for (const keyword of keywordDocs) {
      const result = keywordMatchesCorpus(keyword, corpusByField);
      if (!result.matched) continue;

      const weight = safeNumber(keyword.weight, 0);
      metadataScore += weight;
      metadataMatches.push({
        pattern: keyword.pattern,
        matchMode: keyword.matchMode || "substring",
        category: keyword.category || "generic",
        weight,
        fields: result.fields,
        source: keyword.source || "custom",
      });
    }

    metadataMatches.sort((a, b) => safeNumber(b.weight, 0) - safeNumber(a.weight, 0));

    // ----- ZIP content scan -----
    const zipUrl = `https://api.github.com/repos/${owner}/${repo}/zipball`;
    const downloaded = await downloadZip(zipUrl);
    tempBase = downloaded.tempBase;
    zipPath = downloaded.zipPath;
    zipBytes = safeNumber(downloaded.zipBytes, 0);

    const extractedRoot = await extractZip(zipPath);

    // Delete ZIP after extraction.
    try {
      await fsp.unlink(zipPath);
      console.log(`[ZIPSCAN] ZIP deleted after extraction: ${zipPath}`);
    } catch {
      // ignore
    }

    const compiledKeywords = await getMalwareKeywordsFromDB();
    const zipScan = await scanFiles(extractedRoot, compiledKeywords);

    // ----- Merge evidence into a single score/match list -----
    const combined = mergeMetadataAndZipMatches(metadataMatches, zipScan.matches);

    // ----- AI (best-effort) -----
    let ai = null;
    try {
      const aiPrompt =
        "You are RepoSmart Malware Detector. You have BOTH GitHub metadata signals and ZIP content keyword matches. " +
        "Decide if the repository is likely malicious. Output STRICT JSON ONLY with fields: " +
        "malicious (boolean), confidence (number 0..1), reasoning (string), indicators (string[]). " +
        "Be conservative: if evidence is weak, set malicious=false and lower confidence.\n\n" +
        `REPO_URL: ${url}\n` +
        `METADATA_SCORE: ${Math.round(safeNumber(metadataScore, 0) * 100) / 100}\n` +
        `ZIP_FILES_SCANNED: ${safeNumber(zipScan.totalFilesScanned, 0)}\n` +
        `ZIP_SUSPICIOUS_FILES: ${Array.isArray(zipScan.suspiciousFiles) ? zipScan.suspiciousFiles.length : 0}\n` +
        `COMBINED_SCORE: ${Math.round(safeNumber(combined.totalScore, 0) * 100) / 100}\n` +
        `TOP_COMBINED_MATCHES_JSON: ${JSON.stringify(combined.matches.slice(0, 50), null, 2)}\n` +
        `TOP_ZIP_SUSPICIOUS_FILES_JSON: ${JSON.stringify(zipScan.suspiciousFiles.slice(0, 25), null, 2)}\n` +
        `REPO_METADATA_JSON: ${JSON.stringify(
          {
            fullName: repoMeta.full_name,
            description: repoMeta.description,
            topics: Array.isArray(repoMeta.topics) ? repoMeta.topics : [],
            defaultBranch: repoMeta.default_branch,
            visibility: repoMeta.visibility,
            stars: safeNumber(repoMeta.stargazers_count, 0),
            forks: safeNumber(repoMeta.forks_count, 0),
            sizeKb: safeNumber(repoMeta.size, 0),
          },
          null,
          2,
        )}`;

      const generated = await openRouterGenerateText(aiPrompt);
      ai = {
        model: generated.model,
        output: generated.text,
        parsed: tryParseJsonObject(generated.text),
      };
    } catch {
      ai = null;
    }

    // Recompute deterministic verdict including AI parsed output.
    const finalVerdict = computeMalwareVerdict({
      totalScore: combined.totalScore,
      matches: combined.matches,
      repoMeta,
      readmeText,
      filePathsText: corpusByField.filePaths,
      aiParsed: ai && ai.parsed ? ai.parsed : null,
    });

    const payload = {
      input: { owner, repo, url },
      repo: {
        fullName: repoMeta.full_name,
        htmlUrl: repoMeta.html_url,
        description: repoMeta.description,
        defaultBranch: repoMeta.default_branch,
        isFork: Boolean(repoMeta.fork),
        visibility: repoMeta.visibility,
        stars: safeNumber(repoMeta.stargazers_count, 0),
        forks: safeNumber(repoMeta.forks_count, 0),
        watchers: safeNumber(repoMeta.watchers_count, 0),
        openIssues: safeNumber(repoMeta.open_issues_count, 0),
        license: repoMeta.license ? repoMeta.license.spdx_id : null,
        topics: Array.isArray(repoMeta.topics) ? repoMeta.topics : [],
        createdAt: repoMeta.created_at,
        updatedAt: repoMeta.updated_at,
        pushedAt: repoMeta.pushed_at,
        sizeKb: safeNumber(repoMeta.size, 0),
      },
      snapshot: {
        files: {
          fileCount: treeInfo.fileCount,
          directoryCount: treeInfo.directoryCount,
          truncated: treeInfo.truncated,
          topLevelCounts: treeInfo.topLevelCounts,
        },
        languages: Object.keys(languages),
        readme: {
          present: isNonEmptyString(readmeText),
          wordCount: isNonEmptyString(readmeText) ? readmeText.split(/\s+/).filter(Boolean).length : 0,
        },
      },
      keywordModel: {
        enabledCount: Array.isArray(keywordDocs) ? keywordDocs.length : 0,
      },
      zipScan: {
        zipBytes: safeNumber(zipBytes, 0),
        totalFilesScanned: safeNumber(zipScan.totalFilesScanned, 0),
        suspiciousFiles: Array.isArray(zipScan.suspiciousFiles) ? zipScan.suspiciousFiles : [],
      },
      verdict: finalVerdict,
      ...buildMalwareRiskMetrics(combined.totalScore),
      patternMatch: {
        totalScore: Math.round(safeNumber(combined.totalScore, 0) * 100) / 100,
        matches: combined.matches.slice(0, 100),
      },
      ai,
    };

    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;

    let message = err instanceof Error ? err.message : "Unable to run malware scan.";

    if (status === 404) {
      message = "Repository not found (or it may be private).";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  } finally {
    try {
      if (typeof tempBase === "string" && tempBase.trim().length > 0) {
        await fsp.rm(tempBase, { recursive: true, force: true });
        console.log(`[ZIPSCAN] Temp directory cleaned up: ${tempBase}`);
      }
    } catch {
      // ignore
    }
  }
};

/**
 * Malware scanning pipeline (ZIP + keyword matching + JS AST hints).
 * Input: { url: string } (or { input: string })
 * Output:
 * {
 *   verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "DANGEROUS_DATASET",
 *   score: number,
 *   matchCount: number,
 *   matches: Array<{ pattern: string, category: string, weight: number, file: string, matchedField: "name"|"path"|"content" }>,
 *   astFindings: { suspiciousFunctions: string[], suspiciousVariables: string[], suspiciousCalls: string[] }
 * }
 */
exports.malwarePipelineScanRepository = async (req, res) => {
  try {
    const url = (req.body && (req.body.url || req.body.repoUrl || req.body.input)) || "";
    const debug =
      Boolean(req.query && (req.query.debug === "1" || req.query.debug === "true")) ||
      Boolean(req.body && req.body.debug);
    const { owner, repo } = parseGithubRepoInput(url);

    const cacheKey = buildMalwarePipelineCacheKey(owner, repo);
    const cached = await redisGetJson(cacheKey);
    if (cached && typeof cached === "object") {
      res.set("X-RepoSmart-Cache", "HIT");
      if (cached.input && typeof cached.input === "object") {
        cached.input = { ...cached.input, url };
      }
      return res.json(cached);
    }

    const alwaysLog = process.env.REPOSMART_PIPELINE_LOG === "1";
    const logPrefix = `[PIPELINE] ${owner}/${repo}`;
    if (debug || alwaysLog) console.log(`${logPrefix} starting scan`);

    const result = await scanGithubRepoForMalwarePipeline({
      owner,
      repo,
      onProgress: (evt) => {
        if (!evt || typeof evt !== "object") return;
        const step = typeof evt.step === "string" ? evt.step : "progress";

        // Always log milestones when debug is enabled (or forced via env).
        if (!(debug || alwaysLog)) return;

        if (step === "download:done") {
          console.log(`${logPrefix} download done (${evt.zipBytes || 0} bytes)`);
          return;
        }
        if (step === "extract:done") {
          console.log(`${logPrefix} extract done (${evt.filesProcessed || 0} files)`);
          return;
        }
        if (step === "keywords:done") {
          console.log(
            `${logPrefix} keywords loaded (sub=${evt.enabledSubstringCount || 0}, re=${evt.enabledRegexCount || 0}, docs=${evt.rawEnabledDocsCount || 0})`,
          );
          return;
        }
        if (step === "scan:done") {
          console.log(
            `${logPrefix} scan done verdict=${evt.verdict} score=${evt.score} matches=${evt.matchCount}`,
          );
          return;
        }

        if (step && (step.endsWith(":start") || step.endsWith(":done"))) {
          console.log(`${logPrefix} ${step}`);
        }
      },
    });

    const shouldLogDetails = debug || alwaysLog || safeNumber(result && result.matchCount, 0) === 0;
    if (shouldLogDetails) {
      const filesProcessed = result && result._debug ? result._debug.filesProcessed : "?";
      const score = result && typeof result.score === "number" ? result.score : "?";
      const matchCount = result && typeof result.matchCount === "number" ? result.matchCount : "?";
      console.log(`${logPrefix} extracted=${filesProcessed} score=${score} matches=${matchCount}`);

      const zipStats = result && result._debug ? result._debug.zipStats : null;
      if (zipStats) console.log(`${logPrefix} zipStats=${JSON.stringify(zipStats)}`);

      const keywordModel = result && result._debug ? result._debug.keywordModel : null;
      if (keywordModel) {
        const view = {
          enabledSubstringCount: keywordModel.enabledSubstringCount,
          enabledRegexCount: keywordModel.enabledRegexCount,
          samplePatterns: Array.isArray(keywordModel.samplePatterns) ? keywordModel.samplePatterns.slice(0, 10) : [],
        };
        console.log(`${logPrefix} keywordModel=${JSON.stringify(view)}`);

        if (safeNumber(keywordModel.enabledSubstringCount, 0) + safeNumber(keywordModel.enabledRegexCount, 0) === 0) {
          console.warn(`${logPrefix} WARNING: no enabled MalwareKeyword patterns found in MongoDB.`);
        }
      }

      // Verify DB connectivity + keyword counts from MongoDB at request-time.
      try {
        const ready = mongoose.connection ? mongoose.connection.readyState : null;
        const dbName = mongoose.connection ? mongoose.connection.name : null;
        const host = mongoose.connection ? mongoose.connection.host : null;
        const kwTotal = await MalwareKeyword.countDocuments({});
        const kwEnabled = await MalwareKeyword.countDocuments({ enabled: true });
        console.log(
          `${logPrefix} mongo={readyState:${ready},db:${dbName},host:${host}} MalwareKeyword={total:${kwTotal},enabled:${kwEnabled}}`,
        );
      } catch {
        console.warn(`${logPrefix} Unable to count MalwareKeyword docs for debug.`);
      }

      const topExtensions =
        result && result._debug && result._debug.fileStats && Array.isArray(result._debug.fileStats.topExtensions)
          ? result._debug.fileStats.topExtensions
          : null;
      if (topExtensions) console.log(`${logPrefix} topExtensions=${JSON.stringify(topExtensions)}`);

      const firstPaths =
        result && result._debug && result._debug.fileStats && Array.isArray(result._debug.fileStats.firstFilePaths)
          ? result._debug.fileStats.firstFilePaths.slice(0, 10)
          : null;
      if (firstPaths) console.log(`${logPrefix} firstFilePaths=${JSON.stringify(firstPaths)}`);

      const byField = result && result._debug && result._debug.matchStats ? result._debug.matchStats.byField : null;
      if (byField) console.log(`${logPrefix} matchByField=${JSON.stringify(byField)}`);
    }

    // Best-effort GitHub metadata for AI context.
    if (debug || alwaysLog) console.log(`${logPrefix} metadata:start`);
    let repoMeta = null;
    let languages = null;
    let readmeText = "";
    let treeInfo = { paths: [] };

    try {
      const repoMetaResp = await githubRequestJson(`/repos/${owner}/${repo}`);
      repoMeta = repoMetaResp.data;
    } catch {
      repoMeta = null;
    }

    try {
      const languagesResp = await githubRequestJson(`/repos/${owner}/${repo}/languages`);
      languages = languagesResp.data || {};
    } catch {
      languages = null;
    }

    try {
      const readmeResp = await githubRequestText(
        `/repos/${owner}/${repo}/readme`,
        undefined,
        "application/vnd.github.raw",
      );
      readmeText = typeof readmeResp.data === "string" ? readmeResp.data : "";
    } catch {
      readmeText = "";
    }

    try {
      const treeResp = await githubRequestJson(`/repos/${owner}/${repo}/git/trees/${repoMeta && repoMeta.default_branch ? repoMeta.default_branch : "HEAD"}`,
        { recursive: 1 },
      );
      const tree = treeResp.data;
      const items = tree && Array.isArray(tree.tree) ? tree.tree : [];
      const filePaths = items
        .filter((item) => item && item.type === "blob" && typeof item.path === "string")
        .map((item) => item.path)
        .slice(0, 500);
      treeInfo = { paths: filePaths };
    } catch {
      treeInfo = { paths: [] };
    }

    const metadataCorpus = buildMetadataCorpus({
      repoMeta: repoMeta || { name: `${owner}/${repo}`, full_name: `${owner}/${repo}`, topics: [] },
      languages: languages || {},
      readmeText,
      treeInfo,
    });

    if (debug || alwaysLog) console.log(`${logPrefix} metadata:done`);

    // Best-effort AI verdict using pipeline evidence.
    // Never downgrade a deterministic DANGEROUS_DATASET or MALICIOUS verdict.
    let ai = null;
    try {
      if (debug || alwaysLog) console.log(`${logPrefix} ai:start`);
      const topMatches = Array.isArray(result.matches) ? result.matches.slice(0, 120) : [];
      const aiPrompt =
        "You are RepoSmart Malware Detector. You analyzed a GitHub repository using keyword matching across file name/path/content and JS AST identifier matching. " +
        "Return STRICT JSON ONLY with fields: verdict (one of SAFE|SUSPICIOUS|MALICIOUS|DANGEROUS_DATASET), confidence (number 0..1), reasoning (string), indicators (string[]). " +
        "Rules: Choose DANGEROUS_DATASET not only for malware sample repositories, but also for threat-intelligence datasets/corpora (e.g., STIX/CTI/TAXII/IOC feeds, MITRE ATT&CK STIX, indicator collections). " +
        "This category can be legitimate/educational but still represents dangerous content. " +
        "Be conservative about escalation to MALICIOUS unless there are strong code-level indicators of harmful behavior. " +
        "If the repository is primarily a dataset/corpus of malware/indicators (especially with STIX/CTI/MITRE/IOC signals in metadata/README/file paths), prefer DANGEROUS_DATASET over SAFE.\n\n" +
        `REPO_INPUT: ${owner}/${repo}\n` +
        `GITHUB_METADATA_JSON: ${JSON.stringify(metadataCorpus, null, 2)}\n` +
        `DETERMINISTIC_VERDICT: ${result.verdict}\n` +
        `SCORE: ${result.score}\n` +
        `MATCH_COUNT: ${result.matchCount}\n` +
        `TOP_MATCHES_JSON: ${JSON.stringify(topMatches, null, 2)}\n` +
        `AST_FINDINGS_JSON: ${JSON.stringify(result.astFindings || {}, null, 2)}`;

      const generated = await openRouterGenerateText(aiPrompt);
      ai = {
        model: generated.model,
        output: generated.text,
        parsed: tryParseJsonObject(generated.text),
      };
      if (debug || alwaysLog) console.log(`${logPrefix} ai:done model=${ai.model}`);
    } catch (err) {
      ai = null;
      if (debug || alwaysLog) {
        const status = err && typeof err.statusCode === "number" ? err.statusCode : null;
        const message = err instanceof Error ? err.message : String(err);
        const compact = (message || "").replace(/\s+/g, " ").trim();
        const preview = compact.length > 220 ? `${compact.slice(0, 220)}...` : compact;
        console.log(`${logPrefix} ai:skip${status ? ` status=${status}` : ""}${preview ? ` reason=${preview}` : ""}`);
      }
    }

    let finalVerdict = result.verdict;
    const aiParsed = ai && ai.parsed ? ai.parsed : null;
    const aiVerdict = aiParsed && typeof aiParsed.verdict === "string" ? aiParsed.verdict : null;
    const aiConfidence = aiParsed && typeof aiParsed.confidence === "number" ? aiParsed.confidence : null;
    const allowed = new Set(["SAFE", "SUSPICIOUS", "MALICIOUS", "DANGEROUS_DATASET"]);
    if (aiVerdict && allowed.has(aiVerdict)) {
      // Default behavior: upgrade when AI is more severe.
      // Safety rule: never downgrade a deterministic MALICIOUS or DANGEROUS_DATASET verdict.
      const rank = { SAFE: 0, SUSPICIOUS: 1, MALICIOUS: 2, DANGEROUS_DATASET: 3 };
      const deterministicRank = rank[result.verdict] ?? 0;
      const aiRank = rank[aiVerdict] ?? 0;

      if (aiRank > deterministicRank) {
        finalVerdict = aiVerdict;
      } else {
        finalVerdict = result.verdict;
      }

      // Allow a narrow downgrade only for false-positive cleanup:
      // SUSPICIOUS -> SAFE when AI is highly confident.
      // (Still never downgrade MALICIOUS or DANGEROUS_DATASET.)
      if (
        result.verdict === "SUSPICIOUS" &&
        aiVerdict === "SAFE" &&
        typeof aiConfidence === "number" &&
        Number.isFinite(aiConfidence) &&
        aiConfidence >= 0.85
      ) {
        finalVerdict = "SAFE";
      }
    }

    // Metadata-based dataset override.
    // Some repos (ex: threat intel datasets like MITRE ATT&CK STIX) may have few/no matches
    // but should still be classified as a dataset rather than SAFE.
    const metadataText = [
      metadataCorpus.name,
      metadataCorpus.description,
      metadataCorpus.topics,
      metadataCorpus.languages,
      metadataCorpus.readme,
      metadataCorpus.filePaths,
    ]
      .filter(Boolean)
      .join("\n")
      .toLowerCase();

    const datasetTerms = ["dataset", "datasets", "stix", "attack-stix", "attack stix", "taxii", "cti", "threat intel", "threat intelligence"];
    const mitreTerms = ["mitre", "attack", "enterprise-attack", "mobile-attack", "ics-attack"]; // dataset families
    const hasDatasetSignal = datasetTerms.some((t) => metadataText.includes(t));
    const hasMitreSignal = mitreTerms.some((t) => metadataText.includes(t));

    if (hasDatasetSignal && hasMitreSignal && finalVerdict === "SAFE") {
      finalVerdict = "DANGEROUS_DATASET";
    }

    const licenseDetection = await detectRepositoryLicense({
      owner,
      repo,
      repoMeta: repoMeta || {},
      treeInfo,
      fetchFileText: fetchRepositoryFileText,
    });

    const contextAdjusted = applyContextAwareRiskAdjustments({
      score: safeNumber(result.score, 0),
      matches: Array.isArray(result.matches) ? result.matches : [],
      readmeText,
    });

    if (ai && ai.parsed && typeof ai.parsed === "object") {
      const baseConfidence = safeNumber(ai.parsed.confidence, 0.5);
      ai.parsed.confidence = Math.round(clamp(baseConfidence + safeNumber(contextAdjusted.adjustments.confidenceAdjustment, 0), 0, 1) * 100) / 100;
    }

    const malwareExplanation = generateMalwareExplanation({
      ...result,
      score: contextAdjusted.adjustedScore,
      verdict: finalVerdict,
    });

    const trustReport = generateTrustReport({
      baseScore: null,
      licenseDetection,
      malwareRisk: {
        normalizedRiskScore: Math.round(clamp((safeNumber(contextAdjusted.adjustedScore, 0) / 25) * 100, 0, 100)),
      },
      readmeSnapshot: {
        present: isNonEmptyString(readmeText),
        hasInstall: /\b(install|installation|getting started|setup)\b/i.test(readmeText || ""),
        hasUsage: /\b(usage|how to use|examples?)\b/i.test(readmeText || ""),
      },
      gitSnapshot: null,
    });

    const payload = {
      ...result,
      verdict: finalVerdict,
      ...buildMalwareRiskMetrics(contextAdjusted.adjustedScore),
      score: contextAdjusted.adjustedScore,
      contextAdjustments: contextAdjusted.adjustments,
      malwareExplanation,
      licenseDetection,
      trustReport,
      ai,

    };

    if (!debug && payload && typeof payload === "object") {
      // Remove debug-only internals by default.
      delete payload._debug;
    }

    await redisSetJson(cacheKey, payload, getMalwarePipelineCacheTtlSeconds());

    res.set("X-RepoSmart-Cache", "MISS");

    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;

    let message = err instanceof Error ? err.message : "Unable to run malware scan.";

    if (status === 404) {
      message = "Repository not found (or it may be private).";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  }
};

/**
 * User anomaly profile + commit behavior detection.
 * Input: { username?: string, profileUrl?: string, lookbackDays?: number }
 */
exports.userAnomalyProfileRepository = async (req, res) => {
  try {
    const usernameInput =
      (req.body && (req.body.username || req.body.githubUsername || req.body.profileUrl || req.body.input)) || "";
    const username = parseGithubUsernameInput(usernameInput);

    const lookbackRaw = Number(req.body && req.body.lookbackDays);
    const lookbackDays = Number.isFinite(lookbackRaw)
      ? clamp(Math.floor(lookbackRaw), 7, 180)
      : 45;

    const nowIso = new Date().toISOString();
    const sinceIso = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000).toISOString();
    const warnings = [];

    const toWarning = (label, err) => {
      const status = err && typeof err.statusCode === "number" ? err.statusCode : null;
      const message = err instanceof Error && isNonEmptyString(err.message)
        ? err.message
        : "Unknown error";
      return status ? `${label}: ${message} (HTTP ${status})` : `${label}: ${message}`;
    };

    const userResp = await githubRequestJson(`/users/${encodeURIComponent(username)}`);
    const user = userResp && userResp.data ? userResp.data : {};

    const events = [];
    const maxPages = 3;

    for (let page = 1; page <= maxPages; page += 1) {
      let eventsResp;
      try {
        eventsResp = await githubRequestJson(
          `/users/${encodeURIComponent(username)}/events/public`,
          { per_page: 100, page },
        );
      } catch (err) {
        // Keep analysis running even if recent events cannot be fetched.
        warnings.push(toWarning(`Unable to fetch public events page ${page}`, err));
        break;
      }

      const batch = Array.isArray(eventsResp && eventsResp.data) ? eventsResp.data : [];
      if (batch.length === 0) break;

      events.push(...batch.filter((evt) => evt && typeof evt.created_at === "string" && evt.created_at >= sinceIso));

      const oldest = batch[batch.length - 1];
      const oldestTs = oldest && typeof oldest.created_at === "string" ? oldest.created_at : null;
      if (oldestTs && oldestTs < sinceIso) break;
    }

    let reposResp;
    try {
      reposResp = await githubRequestJson(
        `/users/${encodeURIComponent(username)}/repos`,
        { per_page: 60, sort: "pushed", direction: "desc" },
      );
    } catch (err) {
      // Continue with empty repo list so score can still be computed from profile/events.
      warnings.push(toWarning("Unable to fetch recent repositories", err));
      reposResp = { data: [] };
    }

    const repos = Array.isArray(reposResp && reposResp.data) ? reposResp.data : [];
    const candidateRepos = repos
      .filter((repo) => repo && typeof repo.full_name === "string")
      .sort((a, b) => {
        const left = typeof a.pushed_at === "string" ? a.pushed_at : "";
        const right = typeof b.pushed_at === "string" ? b.pushed_at : "";
        return right.localeCompare(left);
      })
      .slice(0, 10);

    const repoCommits = await Promise.all(
      candidateRepos.map(async (repo) => {
        const fullName = typeof repo.full_name === "string" ? repo.full_name : "";
        const [owner, repoName] = fullName.split("/");

        if (!owner || !repoName) {
          return { repo: fullName || "unknown", commits: [] };
        }

        try {
          const commitsResp = await githubRequestJson(
            `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/commits`,
            {
              author: username,
              since: sinceIso,
              per_page: 100,
            },
          );

          const commits = Array.isArray(commitsResp && commitsResp.data) ? commitsResp.data : [];
          return { repo: fullName, commits };
        } catch {
          // Ignore inaccessible/private repos.
          return { repo: fullName, commits: [] };
        }
      }),
    );

    const analysis = analyzeUserProfileAndCommits({
      user,
      events,
      repoCommits,
      lookbackDays,
      nowIso,
    });

    const payload = {
      username,
      lookbackDays,
      since: sinceIso,
      account: {
        id: user && user.id,
        login: user && user.login,
        createdAt: user && user.created_at,
        publicRepos: safeNumber(user && user.public_repos, 0),
        followers: safeNumber(user && user.followers, 0),
        following: safeNumber(user && user.following, 0),
      },
      ...analysis,
    };

    if (warnings.length > 0) {
      payload.warnings = warnings;
      payload.partialData = true;
    }

    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;
    let message = err instanceof Error ? err.message : "Unable to analyze user profile and commits.";

    if (status === 404) {
      message = "GitHub user not found.";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    if (status === 429) {
      message = "GitHub API temporarily rate-limited this request. Please retry in a minute.";
    }

    if (status === 403 && /secondary rate limit|abuse detection/i.test(message)) {
      message = "GitHub temporarily throttled this request due to high activity. Please retry shortly.";
    }

    res.status(status).json({ message });
  }
};

/**
 * Repository collaborator outlier analysis with deterministic + OpenRouter AI reasoning.
 * Input: { url?: string, lookbackDays?: number, topCollaborators?: number }
 */
exports.collaboratorOutliersRepository = async (req, res) => {
  try {
    const url = (req.body && (req.body.url || req.body.repoUrl || req.body.input)) || "";
    const { owner, repo } = parseGithubRepoInput(url);

    const lookbackRaw = Number(req.body && req.body.lookbackDays);
    const lookbackDays = Number.isFinite(lookbackRaw)
      ? clamp(Math.floor(lookbackRaw), 14, 365)
      : 90;

    const topRaw = Number(req.body && req.body.topCollaborators);
    const topCollaborators = Number.isFinite(topRaw)
      ? clamp(Math.floor(topRaw), 3, 20)
      : 10;

    const sinceIso = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000).toISOString();

    const [repoMetaResp, contributorsResp] = await Promise.all([
      githubRequestJson(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`),
      githubRequestJson(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contributors`, {
        per_page: 100,
        anon: false,
      }),
    ]);

    const repoMeta = repoMetaResp && repoMetaResp.data ? repoMetaResp.data : {};
    const contributors = Array.isArray(contributorsResp && contributorsResp.data) ? contributorsResp.data : [];

    if (contributors.length === 0) {
      return res.status(404).json({ message: "No collaborators found for this repository." });
    }

    const selectedContributors = contributors
      .filter((item) => item && typeof item.login === "string")
      .sort((a, b) => safeNumber(b.contributions, 0) - safeNumber(a.contributions, 0))
      .slice(0, topCollaborators);

    const collaboratorProfiles = await Promise.all(
      selectedContributors.map(async (item) => {
        const login = item.login;
        const lifetimeContributions = safeNumber(item.contributions, 0);

        let commits = [];
        try {
          const commitsResp = await githubRequestJson(
            `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits`,
            {
              author: login,
              since: sinceIso,
              per_page: 100,
            },
          );

          commits = Array.isArray(commitsResp && commitsResp.data) ? commitsResp.data : [];
        } catch {
          commits = [];
        }

        const signals = buildCollaboratorCommitSignals(commits);

        return {
          login,
          avatarUrl: typeof item.avatar_url === "string" ? item.avatar_url : null,
          profileUrl: typeof item.html_url === "string" ? item.html_url : null,
          lifetimeContributions,
          ...signals,
        };
      }),
    );

    const totalContributions = collaboratorProfiles.reduce(
      (sum, profile) => sum + safeNumber(profile.lifetimeContributions, 0),
      0,
    );
    const medianContributions = computeMedian(collaboratorProfiles.map((profile) => profile.lifetimeContributions));

    const deterministic = collaboratorProfiles.map((profile) => {
      const score = computeCollaboratorDeterministicScore(profile, {
        totalContributions,
        medianContributions,
      });

      return {
        ...profile,
        deterministic: score,
      };
    });

    const deterministicOutliers = deterministic
      .filter((profile) => safeNumber(profile.deterministic && profile.deterministic.score, 0) >= 40)
      .sort(
        (a, b) =>
          safeNumber(b.deterministic && b.deterministic.score, 0) -
          safeNumber(a.deterministic && a.deterministic.score, 0),
      )
      .slice(0, 8)
      .map((profile) => ({
        login: profile.login,
        score: safeNumber(profile.deterministic && profile.deterministic.score, 0),
        riskLevel: profile.deterministic ? profile.deterministic.riskLevel : "LOW",
        reasons: profile.deterministic && Array.isArray(profile.deterministic.reasons)
          ? profile.deterministic.reasons
          : [],
      }));

    const aiInput = {
      repository: {
        owner,
        repo,
        fullName: repoMeta && repoMeta.full_name,
        createdAt: repoMeta && repoMeta.created_at,
        pushedAt: repoMeta && repoMeta.pushed_at,
        stargazersCount: safeNumber(repoMeta && repoMeta.stargazers_count, 0),
        forksCount: safeNumber(repoMeta && repoMeta.forks_count, 0),
      },
      lookbackDays,
      collaboratorProfiles: deterministic.map((profile) => ({
        login: profile.login,
        lifetimeContributions: profile.lifetimeContributions,
        analyzedCommits: profile.analyzedCommits,
        suspiciousMessageRatio: Math.round(safeNumber(profile.suspiciousMessageRatio, 0) * 1000) / 1000,
        nightCommitRatio: Math.round(safeNumber(profile.nightCommitRatio, 0) * 1000) / 1000,
        weekendCommitRatio: Math.round(safeNumber(profile.weekendCommitRatio, 0) * 1000) / 1000,
        recencyBurstRatio: Math.round(safeNumber(profile.recencyBurstRatio, 0) * 1000) / 1000,
        deterministicScore: safeNumber(profile.deterministic && profile.deterministic.score, 0),
        deterministicRiskLevel: profile.deterministic ? profile.deterministic.riskLevel : "LOW",
      })),
      deterministicOutliers,
    };

    let ai = null;
    try {
      const prompt =
        "You are a security analyst. Analyze repository collaborators for contribution outliers and suspicious activity. " +
        "Return STRICT JSON ONLY with this schema: " +
        "{\"outliers\":[{\"login\":string,\"riskLevel\":\"LOW\"|\"MEDIUM\"|\"HIGH\",\"score\":number,\"reasons\":string[]}],\"teamRiskSummary\":{\"riskLevel\":\"LOW\"|\"MEDIUM\"|\"HIGH\",\"summary\":string},\"monitoringRecommendations\":string[]}. " +
        "Use deterministic signals heavily; do not hallucinate. Keep reasons concise and concrete.\n\n" +
        `COLLABORATOR_DATA_JSON:\n${JSON.stringify(aiInput, null, 2)}`;

      const generated = await openRouterGenerateText(prompt);
      ai = {
        model: generated.model,
        output: generated.text,
        parsed: tryParseJsonObject(generated.text),
      };
    } catch (err) {
      ai = {
        model: null,
        output: null,
        parsed: null,
        error: err instanceof Error ? err.message : "AI analysis unavailable.",
      };
    }

    const payload = {
      input: {
        url,
        owner,
        repo,
        lookbackDays,
        topCollaborators,
      },
      repository: {
        fullName: repoMeta && repoMeta.full_name,
        createdAt: repoMeta && repoMeta.created_at,
        pushedAt: repoMeta && repoMeta.pushed_at,
      },
      summary: {
        collaboratorsAnalyzed: deterministic.length,
        totalContributions,
        medianContributions,
        deterministicOutlierCount: deterministicOutliers.length,
      },
      collaborators: deterministic,
      deterministicOutliers,
      ai,
    };

    res.json(payload);
  } catch (err) {
    const status = err && typeof err.statusCode === "number" ? err.statusCode : 500;
    let message = err instanceof Error ? err.message : "Unable to analyze collaborator outliers.";

    if (status === 404) {
      message = "Repository not found (or it may be private).";
    }

    if (status === 403 && /rate limit/i.test(message)) {
      message = "GitHub API rate limit exceeded. Set GITHUB_TOKEN in server environment to increase limits.";
    }

    res.status(status).json({ message });
  }
};
