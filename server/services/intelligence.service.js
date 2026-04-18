function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function safeNumber(value, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function safeLower(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function toTitle(value) {
  return String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function uniqueStrings(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  const seen = new Set();
  for (const value of values) {
    const text = typeof value === "string" ? value.trim() : "";
    if (!text) continue;
    const key = text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(text);
  }
  return out;
}

function buildLicensePatterns() {
  return [
    { spdx: "MIT", aliases: ["mit license", "permission is hereby granted, free of charge"] },
    { spdx: "Apache-2.0", aliases: ["apache license", "version 2.0, january 2004", "apache-2.0"] },
    { spdx: "GPL-3.0", aliases: ["gnu general public license", "either version 3 of the license", "gplv3"] },
    { spdx: "GPL-2.0", aliases: ["gnu general public license", "either version 2 of the license", "gplv2"] },
    { spdx: "BSD-3-Clause", aliases: ["redistribution and use in source and binary forms", "neither the name of"] },
    { spdx: "BSD-2-Clause", aliases: ["redistribution and use in source and binary forms", "provided that the following conditions are met"] },
    { spdx: "MPL-2.0", aliases: ["mozilla public license", "mpl 2.0"] },
    { spdx: "ISC", aliases: ["the isc license", "permission to use, copy, modify"] },
    { spdx: "Unlicense", aliases: ["this is free and unencumbered software released into the public domain", "the unlicense"] },
  ];
}

function parseLicenseFromContent(content) {
  const text = safeLower(content);
  if (!text) return null;

  const patterns = buildLicensePatterns();
  for (const pattern of patterns) {
    const hits = pattern.aliases.filter((alias) => text.includes(safeLower(alias))).length;
    if (hits >= 2) {
      return { license: pattern.spdx, confidence: "high" };
    }
    if (hits >= 1) {
      return { license: pattern.spdx, confidence: "medium" };
    }
  }

  if (text.includes("license")) {
    return { license: "UNKNOWN_LICENSE_TEXT", confidence: "low" };
  }

  return null;
}

async function detectRepositoryLicense({ owner, repo, repoMeta, treeInfo, fetchFileText }) {
  const apiLicense = repoMeta && repoMeta.license && typeof repoMeta.license === "object" ? repoMeta.license : null;
  const apiSpdx = apiLicense && typeof apiLicense.spdx_id === "string" ? apiLicense.spdx_id.trim() : "";

  if (apiSpdx && apiSpdx.toUpperCase() !== "NOASSERTION") {
    return {
      license: apiSpdx,
      confidence: "high",
      source: "github_api",
    };
  }

  const paths = Array.isArray(treeInfo && treeInfo.paths) ? treeInfo.paths : [];
  const candidatePaths = paths.filter((p) => {
    const lower = safeLower(p);
    return (
      lower === "license" ||
      lower === "copying" ||
      lower.endsWith("/license") ||
      lower.endsWith("/license.md") ||
      lower.endsWith("/license.txt") ||
      lower.endsWith("/copying") ||
      lower.endsWith("/copying.md") ||
      lower.endsWith("/copying.txt")
    );
  });

  for (const path of candidatePaths.slice(0, 6)) {
    try {
      const content = await fetchFileText({ owner, repo, filePath: path });
      const parsed = parseLicenseFromContent(content);
      if (parsed) {
        return {
          license: parsed.license,
          confidence: parsed.confidence,
          source: "file_scan",
          matchedFile: path,
        };
      }
    } catch {
      // Ignore per-file read failures and continue scanning candidates.
    }
  }

  return {
    license: "MISSING",
    confidence: "low",
    source: "not_found",
    riskImpact: "HIGH",
  };
}

function getCategoryExplanation(category) {
  const value = safeLower(category);
  if (value.includes("command") || value.includes("execution")) {
    return "Detected command execution primitives that can run arbitrary code.";
  }
  if (value.includes("exfil") || value.includes("network")) {
    return "Detected outbound communication patterns that may exfiltrate data.";
  }
  if (value.includes("obfus") || value.includes("encode") || value.includes("base64")) {
    return "Detected obfuscation patterns that can conceal runtime behavior.";
  }
  if (value.includes("credential") || value.includes("password") || value.includes("token") || value.includes("keylog")) {
    return "Detected patterns related to credential access or secret harvesting.";
  }
  if (value.includes("persistence") || value.includes("autorun") || value.includes("startup")) {
    return "Detected persistence-related patterns that may survive restarts.";
  }
  if (value.includes("mitre")) {
    return "Detected indicators mapped to MITRE ATT&CK style techniques.";
  }
  return "Detected suspicious indicators associated with malware-like behavior.";
}

function getPathDampeningMultiplier(filePath) {
  const lower = safeLower(filePath);
  if (!lower) return 1;
  if (lower.startsWith("node_modules/") || lower.includes("/node_modules/")) return 0.2;
  if (lower.startsWith("test/") || lower.includes("/test/") || lower.includes("/tests/") || lower.includes("/__tests__/")) return 0.35;
  if (lower.startsWith("docs/") || lower.includes("/docs/") || lower.endsWith(".md")) return 0.45;
  return 1;
}

function calculateFileDiversity(matches) {
  const list = Array.isArray(matches) ? matches : [];
  const files = new Set();
  const byPattern = new Map();

  for (const match of list) {
    const pattern = typeof match && match && typeof match.pattern === "string" ? match.pattern : null;
    const file = typeof match && match && typeof match.file === "string" ? match.file : null;
    if (file) files.add(file);
    if (!pattern || !file) continue;
    const existing = byPattern.get(pattern) || new Set();
    existing.add(file);
    byPattern.set(pattern, existing);
  }

  let broadPatterns = 0;
  for (const fileSet of byPattern.values()) {
    if (fileSet.size >= 4) broadPatterns += 1;
  }

  return {
    uniqueFiles: files.size,
    broadPatternCount: broadPatterns,
    singleFileSignal: files.size <= 1,
  };
}

function applyContextAwareRiskAdjustments({ score, matches, readmeText }) {
  const list = Array.isArray(matches) ? matches : [];
  const safeScore = safeNumber(score, 0);

  let dampenedScore = 0;
  for (const match of list) {
    const base = safeNumber(match && match.weight, 0);
    const multiplier = getPathDampeningMultiplier(match && match.file);
    dampenedScore += base * multiplier;
  }

  // Keep deterministic score stable if matches are empty.
  if (list.length === 0) {
    dampenedScore = safeScore;
  }

  const readme = safeLower(readmeText);
  const intentTerms = ["security research", "pentesting", "educational", "for research", "for education only"];
  const hasResearchIntent = intentTerms.some((term) => readme.includes(term));

  let intentMultiplier = 1;
  if (hasResearchIntent) {
    intentMultiplier = 0.9;
  }

  const diversity = calculateFileDiversity(list);
  let confidenceAdjustment = 0;
  if (diversity.broadPatternCount >= 2 || diversity.uniqueFiles >= 5) {
    confidenceAdjustment += 0.08;
  }
  if (diversity.singleFileSignal) {
    confidenceAdjustment -= 0.1;
  }

  const adjustedScore = Math.round(dampenedScore * intentMultiplier * 100) / 100;

  return {
    adjustedScore,
    adjustments: {
      pathDampeningApplied: Math.round((safeScore - dampenedScore) * 100) / 100,
      intentMultiplier,
      hasResearchIntent,
      fileDiversity: diversity,
      confidenceAdjustment,
    },
  };
}

function generateMalwareExplanation(scanResult) {
  const result = scanResult && typeof scanResult === "object" ? scanResult : {};
  const score = safeNumber(result.score, 0);
  const matchCount = safeNumber(result.matchCount, Array.isArray(result.matches) ? result.matches.length : 0);
  const verdict = String(result.verdict || "SAFE").toUpperCase();
  const matches = Array.isArray(result.matches) ? result.matches : [];

  const byCategory = new Map();
  for (const match of matches) {
    const category = isNonEmptyString(match && match.category) ? match.category : "generic";
    const current = byCategory.get(category) || { totalWeight: 0, patterns: new Set(), count: 0 };
    current.totalWeight += safeNumber(match && match.weight, 0);
    if (isNonEmptyString(match && match.pattern)) current.patterns.add(match.pattern.trim());
    current.count += 1;
    byCategory.set(category, current);
  }

  const sortedCategories = Array.from(byCategory.entries()).sort((a, b) => b[1].totalWeight - a[1].totalWeight);
  const safeTotal = Math.max(1, sortedCategories.reduce((sum, [, value]) => sum + value.totalWeight, 0));

  const technicalDetails = sortedCategories.slice(0, 5).map(([category, value]) => ({
    category,
    matchedPatterns: Array.from(value.patterns).slice(0, 8),
    riskContribution: Math.round((value.totalWeight / safeTotal) * 100),
  }));

  const keyFindings = technicalDetails.map((detail) => {
    const base = getCategoryExplanation(detail.category);
    if (detail.matchedPatterns.length > 0) {
      return `${base} Matched: ${detail.matchedPatterns.slice(0, 3).join(", ")}.`;
    }
    return base;
  });

  const categoryNames = sortedCategories.map(([category]) => category);
  const hasExecution = categoryNames.some((name) => safeLower(name).includes("execution") || safeLower(name).includes("command"));
  const hasExfil = categoryNames.some((name) => safeLower(name).includes("exfil") || safeLower(name).includes("network"));
  const hasObfuscation = categoryNames.some((name) => safeLower(name).includes("obfus") || safeLower(name).includes("base64"));

  const combinations = [];
  if (hasExecution && hasExfil) {
    combinations.push("execution + exfiltration");
  }
  if (hasExecution && hasObfuscation) {
    combinations.push("execution + obfuscation");
  }

  const summary =
    verdict === "MALICIOUS"
      ? `This repository shows strong signs of suspicious behavior with score ${score} across ${matchCount} indicators.`
      : verdict === "SUSPICIOUS"
        ? `This repository contains notable suspicious patterns with score ${score} across ${matchCount} indicators.`
        : `This repository has limited suspicious signals (score ${score}) and currently appears lower risk.`;

  const verdictReason = combinations.length > 0
    ? `Combination of ${combinations.join(" and ")} patterns indicates elevated risk.`
    : `Verdict is based on weighted category evidence across ${matchCount} matched indicators.`;

  return {
    summary,
    keyFindings: keyFindings.slice(0, 6),
    technicalDetails,
    combinations,
    verdictReason,
  };
}

function recommendationPriority(action) {
  const text = safeLower(action);
  if (
    text.includes("license") ||
    text.includes("secrets") ||
    text.includes("dependency") ||
    text.includes("security") ||
    text.includes("command") ||
    text.includes("exfil")
  ) {
    return "HIGH";
  }
  if (text.includes("test") || text.includes("ci") || text.includes("lint")) {
    return "MEDIUM";
  }
  return "LOW";
}

function buildStructuredRecommendations(recommendations) {
  const values = uniqueStrings(Array.isArray(recommendations) ? recommendations : []);
  return values.slice(0, 6).map((action) => ({
    priority: recommendationPriority(action),
    action,
  }));
}

function generateAIInsights({ metadata, aiParsed, trustReport }) {
  const parsed = aiParsed && typeof aiParsed === "object" ? aiParsed : {};
  const repo = metadata && metadata.repo && typeof metadata.repo === "object" ? metadata.repo : {};

  const summary = isNonEmptyString(parsed.summary)
    ? String(parsed.summary).trim()
    : `${repo.fullName || "Repository"} analysis is based on metadata and security signals only.`;

  const strengths = uniqueStrings(Array.isArray(parsed.strengths) ? parsed.strengths : []);
  const risks = uniqueStrings(Array.isArray(parsed.risks) ? parsed.risks : []);
  const recommendationInput =
    Array.isArray(parsed.recommendations) && parsed.recommendations.length > 0
      ? parsed.recommendations
      : [];

  const recommendations = buildStructuredRecommendations(recommendationInput);

  const trustScoreReasoning = isNonEmptyString(parsed.trustScoreReasoning)
    ? String(parsed.trustScoreReasoning).trim()
    : `Trust score ${safeNumber(trustReport && trustReport.trustScore, 0)} is derived from code safety, documentation, license quality, and activity signals.`;

  return {
    summary,
    strengths: strengths.slice(0, 6),
    risks: risks.slice(0, 6),
    trustScoreReasoning,
    recommendations,
  };
}

function generateTrustReport({ baseScore, licenseDetection, malwareRisk, readmeSnapshot, gitSnapshot }) {
  const score = baseScore && typeof baseScore === "object" ? baseScore : {};
  const breakdown = Array.isArray(score.breakdown) ? score.breakdown : [];

  const documentationRaw = breakdown.find((x) => x && x.key === "documentation");
  const codeRaw = breakdown.find((x) => x && x.key === "codeQuality");
  const gitRaw = breakdown.find((x) => x && x.key === "git");

  const documentation = documentationRaw
    ? Math.round((safeNumber(documentationRaw.score, 0) / Math.max(1, safeNumber(documentationRaw.max, 1))) * 100)
    : Math.round(
      (safeNumber(readmeSnapshot && readmeSnapshot.present, 0) ? 45 : 0) +
      (safeNumber(readmeSnapshot && readmeSnapshot.hasInstall, 0) ? 25 : 0) +
      (safeNumber(readmeSnapshot && readmeSnapshot.hasUsage, 0) ? 30 : 0),
    );

  const codeSafetyBase = codeRaw
    ? Math.round((safeNumber(codeRaw.score, 0) / Math.max(1, safeNumber(codeRaw.max, 1))) * 100)
    : 60;

  const malwarePenalty = safeNumber(malwareRisk && malwareRisk.normalizedRiskScore, 0);
  const codeSafety = clamp(Math.round(codeSafetyBase - malwarePenalty * 0.35), 0, 100);

  const license = licenseDetection && licenseDetection.license === "MISSING" ? 0 : 90;

  const activity = gitRaw
    ? Math.round((safeNumber(gitRaw.score, 0) / Math.max(1, safeNumber(gitRaw.max, 1))) * 100)
    : clamp(
      Math.round(
        Math.min(70, safeNumber(gitSnapshot && gitSnapshot.commitsLast90Days, 0) * 4) +
        Math.min(30, safeNumber(gitSnapshot && gitSnapshot.activeCommitDaysLast90Days, 0) * 2),
      ),
      0,
      100,
    );

  const trustScore = Math.round(codeSafety * 0.4 + documentation * 0.25 + license * 0.2 + activity * 0.15);

  const verdict = trustScore >= 80 ? "Low Risk" : trustScore >= 60 ? "Moderate Risk" : trustScore >= 40 ? "Elevated Risk" : "High Risk";

  const explanationParts = [];
  if (licenseDetection && licenseDetection.license === "MISSING") {
    explanationParts.push("missing license");
  }
  if (malwarePenalty >= 50) {
    explanationParts.push("high suspicious malware signals");
  } else if (malwarePenalty >= 25) {
    explanationParts.push("moderate suspicious malware signals");
  }
  if (documentation < 50) {
    explanationParts.push("weak documentation");
  }

  const explanation = explanationParts.length > 0
    ? `Score reduced due to ${explanationParts.join(" and ")}.`
    : "Score reflects balanced signals across safety, documentation, licensing, and maintenance activity.";

  return {
    trustScore,
    breakdown: {
      codeSafety,
      documentation,
      license,
      activity,
    },
    verdict,
    explanation,
  };
}

module.exports = {
  detectRepositoryLicense,
  generateMalwareExplanation,
  applyContextAwareRiskAdjustments,
  generateAIInsights,
  generateTrustReport,
  getCategoryExplanation,
};
