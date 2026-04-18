// function extractRepoFeatures({ files, astFindings, matches }) {
//     const totalFiles = files.length;

//     let jsLikeFiles = 0;
//     let envFiles = 0;
//     let totalSize = 0;

//     for (const f of files) {
//         const lowerPath = typeof f.filePath === "string" ? f.filePath.toLowerCase() : "";
//         if (/(\.js|\.jsx|\.ts|\.tsx)$/.test(lowerPath)) jsLikeFiles++;
//         if (/(^|\/)\.env(\..+)?$/.test(lowerPath)) envFiles++;
//         totalSize += f.content.length;
//     }

//     const avgFileSize = totalFiles > 0 ? totalSize / totalFiles : 0;

//     return {
//         totalFiles,
//         jsRatio: jsLikeFiles / (totalFiles || 1),
//         envCount: envFiles,
//         avgFileSize,
//         suspiciousFunctions: astFindings.suspiciousFunctions.length,
//         suspiciousVariables: astFindings.suspiciousVariables.length,
//         suspiciousCalls: astFindings.suspiciousCalls.length,
//         matchCount: matches.length,
//     };
// }

// const ANOMALY_FEATURES = [
//     { key: "totalFiles", label: "Total files", baseline: 60, mode: "both", weight: 0.6, cap: 2.5 },
//     { key: "jsRatio", label: "JS/TS ratio", baseline: 0.45, mode: "both", weight: 1.0, cap: 2.0 },
//     { key: "envCount", label: "ENV files", baseline: 0, mode: "high", weight: 0.8, cap: 2.0 },
//     { key: "avgFileSize", label: "Avg file size", baseline: 2200, mode: "both", scale: "log", weight: 0.7, cap: 2.8 },
//     { key: "suspiciousCalls", label: "Suspicious calls", baseline: 1, mode: "high", weight: 1.2, cap: 3.0 },
//     { key: "suspiciousFunctions", label: "Suspicious functions", baseline: 1, mode: "high", weight: 1.0, cap: 2.8 },
//     { key: "suspiciousVariables", label: "Suspicious variables", baseline: 2, mode: "high", weight: 1.0, cap: 2.8 },
//     { key: "matchCount", label: "Keyword matches", baseline: 24, mode: "high", weight: 1.1, cap: 3.2 },
// ];

// function safeNumber(value, fallback = 0) {
//     return typeof value === "number" && Number.isFinite(value) ? value : fallback;
// }

// function deviation(val, base) {
//     return Math.abs(safeNumber(val, 0) - safeNumber(base, 0)) / (safeNumber(base, 0) + 1);
// }

// function highOnlyDeviation(val, base) {
//     const actual = safeNumber(val, 0);
//     const baseline = safeNumber(base, 0);
//     if (actual <= baseline) return 0;
//     return (actual - baseline) / (baseline + 1);
// }

// function logDeviation(val, base) {
//     const actual = Math.max(0, safeNumber(val, 0));
//     const baseline = Math.max(0, safeNumber(base, 0));
//     return Math.abs(Math.log((actual + 1) / (baseline + 1)));
// }

// function getAnomalyBreakdown(features) {
//     const breakdown = ANOMALY_FEATURES.map((row) => {
//         const actual = safeNumber(features && features[row.key], 0);
//         const baseline = safeNumber(row.baseline, 0);
//         const rawDeviation =
//             row.scale === "log"
//                 ? logDeviation(actual, baseline)
//                 : row.mode === "high"
//                     ? highOnlyDeviation(actual, baseline)
//                     : deviation(actual, baseline);

//         const weightedImpact = clamp(rawDeviation * safeNumber(row.weight, 1), 0, safeNumber(row.cap, 5));
//         const impact = Math.round(weightedImpact * 1000) / 1000;

//         return {
//             key: row.key,
//             label: row.label,
//             actual,
//             baseline,
//             impact,
//         };
//     });

//     breakdown.sort((a, b) => b.impact - a.impact);
//     return breakdown;
// }

// function computeAnomalyScore(features) {
//     const breakdown = getAnomalyBreakdown(features);
//     const score = breakdown.reduce((sum, row) => sum + safeNumber(row.impact, 0), 0);
//     return Math.round(score * 10) / 10;
// }

// function clamp(value, min, max) {
//     return Math.max(min, Math.min(max, value));
// }

// function normalizeAnomalyScore(rawScore) {
//     const safeRaw = Number.isFinite(rawScore) ? rawScore : 0;
//     // Scale raw anomaly distance into a UI-friendly 0..100 score.
//     return clamp(Math.round(safeRaw * 12), 0, 100);
// }

// function deriveAnomalyRisk(score) {
//     if (score >= 75) return "HIGH";
//     if (score >= 40) return "MEDIUM";
//     return "LOW";
// }

// function summarizeAnomalies(features) {
//     const anomalies = [];
//     if (!features || typeof features !== "object") return anomalies;

//     const totalFiles = safeNumber(features.totalFiles, 0);
//     const matchCount = safeNumber(features.matchCount, 0);
//     const matchDensity = totalFiles > 0 ? matchCount / totalFiles : matchCount;

//     if ((features.suspiciousCalls || 0) >= 8) {
//         anomalies.push("High volume of suspicious runtime/API calls");
//     }
//     if ((features.suspiciousFunctions || 0) >= 6) {
//         anomalies.push("Many suspicious function identifiers detected");
//     }
//     if ((features.suspiciousVariables || 0) >= 10) {
//         anomalies.push("Large number of sensitive variable identifiers");
//     }
//     if (matchCount >= 60 || matchDensity >= 3) {
//         anomalies.push("Unusually high malicious keyword match density");
//     }
//     if ((features.envCount || 0) >= 3) {
//         anomalies.push("Multiple environment credential files detected");
//     }

//     if ((features.jsRatio || 0) <= 0.05 && (features.totalFiles || 0) >= 30) {
//         anomalies.push("Repository structure is atypical for scanned language mix");
//     }

//     return anomalies;
// }

// function computeFinalVerdict({ baseScore, anomalyScore }) {
//     // If strong anomaly but low malware score, escalate to SUSPICIOUS.
//     if (anomalyScore >= 4.5 && baseScore < 15) {
//         return "SUSPICIOUS";
//     }
//     return null; // fallback to existing verdict
// }

// module.exports = {
//     extractRepoFeatures,
//     computeAnomalyScore,
//     getAnomalyBreakdown,
//     normalizeAnomalyScore,
//     deriveAnomalyRisk,
//     summarizeAnomalies,
//     computeFinalVerdict,
// };

function safeNumber(value, fallback = 0) {
    return typeof value === "number" && Number.isFinite(value)
        ? value
        : fallback;
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

/* -----------------------------
   FEATURE EXTRACTION
----------------------------- */
function extractRepoFeatures({ files, astFindings, matches }) {
    const totalFiles = files.length;

    let jsFiles = 0;
    let envFiles = 0;
    let totalSize = 0;

    for (const f of files) {
        const path = (f.filePath || "").toLowerCase();

        if (/\.(js|jsx|ts|tsx)$/.test(path)) jsFiles++;
        if (/(^|\/)\.env(\..+)?$/.test(path)) envFiles++;

        totalSize += typeof f.content === "string" ? f.content.length : 0;
    }

    const avgFileSize = totalFiles ? totalSize / totalFiles : 0;

    const matchCount = Array.isArray(matches) ? matches.length : 0;

    const suspiciousFunctions = astFindings?.suspiciousFunctions?.length || 0;
    const suspiciousVariables = astFindings?.suspiciousVariables?.length || 0;
    const suspiciousCalls = astFindings?.suspiciousCalls?.length || 0;

    return {
        totalFiles,
        jsRatio: jsFiles / (totalFiles || 1),
        envCount: envFiles,
        avgFileSize,

        suspiciousFunctions,
        suspiciousVariables,
        suspiciousCalls,
        matchCount,

        // IMPORTANT FIX: reduce small repo bias
        matchDensity: matchCount / Math.sqrt(totalFiles || 1),

        // smoother AST density
        suspiciousDensity:
            (suspiciousCalls + suspiciousFunctions + suspiciousVariables) /
            Math.sqrt(totalFiles || 1),
    };
}

/* -----------------------------
   SIZE-AWARE BASELINES
----------------------------- */
const SIZE_PROFILES = [
    {
        id: "small",
        maxFiles: 40,
        baselines: {
            totalFiles: 24,
            jsRatio: 0.72,
            envCount: 1,
            avgFileSize: 1800,
            suspiciousFunctions: 1,
            suspiciousVariables: 2,
            suspiciousCalls: 1,
            matchDensity: 1.4,
            suspiciousDensity: 1.6,
        },
        reasonScale: 1.0,
    },
    {
        id: "medium",
        maxFiles: 220,
        baselines: {
            totalFiles: 110,
            jsRatio: 0.62,
            envCount: 3,
            avgFileSize: 2400,
            suspiciousFunctions: 3,
            suspiciousVariables: 5,
            suspiciousCalls: 3,
            matchDensity: 1.15,
            suspiciousDensity: 1.1,
        },
        reasonScale: 1.6,
    },
    {
        id: "large",
        maxFiles: Number.POSITIVE_INFINITY,
        baselines: {
            totalFiles: 420,
            jsRatio: 0.52,
            envCount: 5,
            avgFileSize: 3000,
            suspiciousFunctions: 7,
            suspiciousVariables: 11,
            suspiciousCalls: 8,
            matchDensity: 0.95,
            suspiciousDensity: 0.95,
        },
        reasonScale: 2.4,
    },
];

const FEATURE_SPECS = [
    { key: "totalFiles", weight: 0.35, scale: "log" },
    { key: "jsRatio", weight: 0.9 },
    { key: "envCount", weight: 0.9, mode: "high" },
    { key: "avgFileSize", weight: 0.5, scale: "log" },

    { key: "suspiciousFunctions", weight: 1.25, mode: "high" },
    { key: "suspiciousVariables", weight: 1.15, mode: "high" },
    { key: "suspiciousCalls", weight: 1.35, mode: "high" },

    { key: "matchDensity", weight: 1.4, mode: "high" },
    { key: "suspiciousDensity", weight: 1.1, mode: "high" },
];

function resolveRepoSizeProfile(totalFiles) {
    const count = Math.max(0, safeNumber(totalFiles, 0));
    return SIZE_PROFILES.find((profile) => count <= profile.maxFiles) || SIZE_PROFILES[SIZE_PROFILES.length - 1];
}

function getBaselineValue(featureKey, totalFiles) {
    const profile = resolveRepoSizeProfile(totalFiles);
    const baseline = profile && profile.baselines ? profile.baselines[featureKey] : 0;
    return safeNumber(baseline, 0);
}

/* -----------------------------
   DEVIATION FUNCTIONS
----------------------------- */
function deviation(val, base) {
    return Math.abs(val - base) / (base + 1);
}

function highOnlyDeviation(val, base) {
    return val <= base ? 0 : (val - base) / (base + 1);
}

function logDeviation(val, base) {
    const a = Math.max(0, val);
    const b = Math.max(0, base);
    return Math.abs(Math.log((a + 1) / (b + 1)));
}

function getAnomalyBreakdown(features) {
    const totalFiles = safeNumber(features?.totalFiles, 0);

    return FEATURE_SPECS.map((f) => {
        const actual = safeNumber(features?.[f.key], 0);
        const base = getBaselineValue(f.key, totalFiles);

        let raw;

        if (f.scale === "log") {
            raw = logDeviation(actual, base);
        } else if (f.mode === "high") {
            raw = highOnlyDeviation(actual, base);
        } else {
            raw = deviation(actual, base);
        }

        const impact = clamp(raw * f.weight, 0, 3);

        return {
            key: f.key,
            actual,
            baseline: base,
            impact: Math.round(impact * 1000) / 1000,
        };
    }).sort((a, b) => b.impact - a.impact);
}

function computeAnomalyScore(features) {
    const breakdown = getAnomalyBreakdown(features);

    let score = 0;

    for (const b of breakdown) {
        const w = safeNumber(b.impact, 0);

        // ignore noise
        if (w < 0.1) continue;

        // nonlinear boost only for strong signals
        score += Math.pow(w, 1.3);
    }

    // normalize by repo complexity
    const normalized =
        score / Math.sqrt(Object.keys(features || {}).length);

    // final bounded score (0–100)
    return clamp(Math.round(normalized * 20), 0, 100);
}

function deriveAnomalyRisk(score) {
    if (score >= 70) return "HIGH";
    if (score >= 40) return "MEDIUM";
    return "LOW";
}

function summarizeAnomalies(features) {
    const reasons = [];

    if (!features) return reasons;

    const totalFiles = safeNumber(features.totalFiles, 0);
    const profile = resolveRepoSizeProfile(totalFiles);
    const reasonScale = safeNumber(profile.reasonScale, 1);

    const suspiciousCallsThreshold = Math.max(4, Math.round(5 * reasonScale));
    const suspiciousFunctionsThreshold = Math.max(4, Math.round(5 * reasonScale));
    const suspiciousVariablesThreshold = Math.max(7, Math.round(8 * reasonScale));
    const envCountThreshold = Math.max(3, Math.round(3 * reasonScale));

    let matchDensityThreshold = 2.1;
    if (profile.id === "small") matchDensityThreshold = 2.6;
    if (profile.id === "large") matchDensityThreshold = 1.8;

    const unusualKeywordThreshold = Math.max(18, Math.round(18 * reasonScale));

    if (safeNumber(features.suspiciousCalls, 0) >= suspiciousCallsThreshold) {
        reasons.push("High number of suspicious API/runtime calls");
    }

    if (safeNumber(features.suspiciousFunctions, 0) >= suspiciousFunctionsThreshold) {
        reasons.push("Suspicious function patterns detected");
    }

    if (safeNumber(features.suspiciousVariables, 0) >= suspiciousVariablesThreshold) {
        reasons.push("Sensitive variable names detected");
    }

    if (safeNumber(features.matchDensity, 0) >= matchDensityThreshold) {
        reasons.push("High keyword match density across repository");
    }

    if (safeNumber(features.envCount, 0) >= envCountThreshold) {
        reasons.push("Multiple environment files detected");
    }

    if (
        safeNumber(features.totalFiles, 0) >= Math.round(safeNumber(profile.baselines.totalFiles, 0) * 0.6) &&
        safeNumber(features.jsRatio, 0) < safeNumber(profile.baselines.jsRatio, 0) * 0.3
    ) {
        reasons.push("Repository language mix is atypical for its project size");
    }

    if (reasons.length === 0 && safeNumber(features.matchCount, 0) >= unusualKeywordThreshold) {
        reasons.push("Unusual keyword activity detected");
    }

    return reasons;
}

function normalizeAnomalyScore(score) {
    const val = safeNumber(score, 0);

    // smooth curve (prevents extreme spikes)
    const normalized = Math.tanh(val / 50) * 100;

    return clamp(Math.round(normalized), 0, 100);
}

function computeFinalVerdict({ baseScore, anomalyScore }) {
    if (anomalyScore >= 80 && baseScore < 20) {
        return "SUSPICIOUS";
    }
    return null;
}

module.exports = {
    extractRepoFeatures,
    computeAnomalyScore,
    getAnomalyBreakdown,
    deriveAnomalyRisk,
    summarizeAnomalies,
    computeFinalVerdict,
    normalizeAnomalyScore
};