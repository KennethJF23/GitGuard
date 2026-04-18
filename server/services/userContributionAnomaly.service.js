function safeNumber(value, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function toTimestamp(value) {
  const ts = new Date(value).getTime();
  return Number.isFinite(ts) ? ts : null;
}

function daysBetween(startIso, endIso) {
  const start = toTimestamp(startIso);
  const end = toTimestamp(endIso);
  if (start === null || end === null) return null;
  const delta = Math.abs(end - start);
  return Math.floor(delta / (1000 * 60 * 60 * 24));
}

function isWeekendDay(dateValue) {
  const d = new Date(dateValue);
  const day = d.getUTCDay();
  return day === 0 || day === 6;
}

function isNightHour(dateValue) {
  const d = new Date(dateValue);
  const hour = d.getUTCHours();
  return hour < 6;
}

function computeMedian(values) {
  const list = (Array.isArray(values) ? values : [])
    .map((v) => safeNumber(v, NaN))
    .filter((v) => Number.isFinite(v))
    .sort((a, b) => a - b);

  if (list.length === 0) return 0;
  const mid = Math.floor(list.length / 2);
  if (list.length % 2 === 0) {
    return (list[mid - 1] + list[mid]) / 2;
  }
  return list[mid];
}

function normalizeCommitRecord(commitRecord) {
  if (!commitRecord || typeof commitRecord !== "object") return null;

  const sha = typeof commitRecord.sha === "string" ? commitRecord.sha : "";
  const commit = commitRecord.commit && typeof commitRecord.commit === "object" ? commitRecord.commit : {};
  const message = typeof commit.message === "string" ? commit.message : "";

  const author = commit.author && typeof commit.author === "object" ? commit.author : {};
  const committer = commit.committer && typeof commit.committer === "object" ? commit.committer : {};
  const committedAt =
    typeof author.date === "string"
      ? author.date
      : typeof committer.date === "string"
        ? committer.date
        : null;

  return {
    sha,
    message,
    committedAt,
  };
}

function groupByDay(events) {
  const map = new Map();
  for (const evt of Array.isArray(events) ? events : []) {
    if (!evt || !evt.created_at) continue;
    const key = String(evt.created_at).slice(0, 10);
    map.set(key, (map.get(key) || 0) + 1);
  }
  return map;
}

function buildCommitMessageSignals(commits) {
  const suspiciousMessageRegexes = [
    /\b(temp|tmp|quick fix|hack|bypass|disable\s+auth|disable\s+security)\b/i,
    /\b(debug\s+only|remove\s+checks|skip\s+validation|hotfix\s+prod)\b/i,
    /\b(wip|test\s+commit|trial|dummy)\b/i,
  ];

  let suspiciousMessageCount = 0;
  let shortMessageCount = 0;

  for (const commit of Array.isArray(commits) ? commits : []) {
    const message = typeof commit.message === "string" ? commit.message.trim() : "";
    if (!message) {
      shortMessageCount += 1;
      continue;
    }

    if (message.length <= 8) {
      shortMessageCount += 1;
    }

    if (suspiciousMessageRegexes.some((re) => re.test(message))) {
      suspiciousMessageCount += 1;
    }
  }

  const total = Math.max(1, Array.isArray(commits) ? commits.length : 0);

  return {
    suspiciousMessageCount,
    suspiciousMessageRatio: suspiciousMessageCount / total,
    shortMessageCount,
    shortMessageRatio: shortMessageCount / total,
  };
}

function deriveRisk(score) {
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

function computeScore(features) {
  let score = 0;

  const accountAgeDays = safeNumber(features.accountAgeDays, 0);
  const activeDays = safeNumber(features.activeDays, 0);
  const pushEvents = safeNumber(features.pushEvents, 0);
  const nightActivityRatio = safeNumber(features.nightActivityRatio, 0);
  const weekendActivityRatio = safeNumber(features.weekendActivityRatio, 0);
  const burstDayRatio = safeNumber(features.burstDayRatio, 0);
  const dominantRepoContributionRatio = safeNumber(features.dominantRepoContributionRatio, 0);
  const suspiciousMessageRatio = safeNumber(features.suspiciousMessageRatio, 0);
  const shortMessageRatio = safeNumber(features.shortMessageRatio, 0);
  const forcePushEventRatio = safeNumber(features.forcePushEventRatio, 0);

  if (accountAgeDays <= 10 && pushEvents >= 25) score += 18;
  else if (accountAgeDays <= 30 && pushEvents >= 20) score += 12;

  if (activeDays > 0) {
    const pushesPerActiveDay = pushEvents / activeDays;
    if (pushesPerActiveDay >= 12) score += 14;
    else if (pushesPerActiveDay >= 7) score += 9;
  }

  if (nightActivityRatio >= 0.7) score += 10;
  else if (nightActivityRatio >= 0.5) score += 6;

  if (weekendActivityRatio >= 0.7) score += 6;

  if (burstDayRatio >= 0.6) score += 12;
  else if (burstDayRatio >= 0.4) score += 7;

  if (dominantRepoContributionRatio >= 0.9) score += 8;
  else if (dominantRepoContributionRatio >= 0.75) score += 5;

  if (suspiciousMessageRatio >= 0.25) score += 12;
  else if (suspiciousMessageRatio >= 0.15) score += 7;

  if (shortMessageRatio >= 0.6) score += 6;
  else if (shortMessageRatio >= 0.4) score += 3;

  if (forcePushEventRatio >= 0.2) score += 14;
  else if (forcePushEventRatio > 0) score += 6;

  return clamp(Math.round(score), 0, 100);
}

function summarizeSignals(features) {
  const reasons = [];

  if (safeNumber(features.accountAgeDays, 0) <= 30 && safeNumber(features.pushEvents, 0) >= 20) {
    reasons.push("New account with unusually high push activity");
  }

  if (safeNumber(features.burstDayRatio, 0) >= 0.4) {
    reasons.push("Contribution bursts concentrated into short windows");
  }

  if (safeNumber(features.nightActivityRatio, 0) >= 0.5) {
    reasons.push("Large share of activity happens at night hours (UTC)");
  }

  if (safeNumber(features.dominantRepoContributionRatio, 0) >= 0.75) {
    reasons.push("Most contributions are concentrated in one repository");
  }

  if (safeNumber(features.suspiciousMessageRatio, 0) >= 0.15) {
    reasons.push("Commit messages contain risky or low-quality change markers");
  }

  if (safeNumber(features.forcePushEventRatio, 0) > 0) {
    reasons.push("Force-push behavior detected in recent events");
  }

  return reasons.slice(0, 6);
}

function analyzeUserProfileAndCommits({ user, events, repoCommits, nowIso, lookbackDays }) {
  const now = typeof nowIso === "string" ? nowIso : new Date().toISOString();
  const accountAgeDays = daysBetween(user && user.created_at, now);

  const cleanEvents = Array.isArray(events) ? events.filter((evt) => evt && evt.created_at) : [];
  const dayBuckets = groupByDay(cleanEvents);
  const activeDays = dayBuckets.size;
  const pushesByDay = Array.from(dayBuckets.values());
  const medianDailyEvents = computeMedian(pushesByDay);

  let pushEvents = 0;
  let forcePushEvents = 0;
  let totalCommitMentions = 0;
  const touchedRepos = new Map();

  for (const evt of cleanEvents) {
    const type = typeof evt.type === "string" ? evt.type : "";
    if (type !== "PushEvent") continue;

    pushEvents += 1;
    const repoName = evt.repo && typeof evt.repo.name === "string" ? evt.repo.name : "unknown";
    touchedRepos.set(repoName, (touchedRepos.get(repoName) || 0) + 1);

    const payload = evt.payload && typeof evt.payload === "object" ? evt.payload : {};
    const size = safeNumber(payload.size, 0);
    totalCommitMentions += Math.max(0, size);

    if (payload.distinct_size > 0 && payload.size > payload.distinct_size) {
      forcePushEvents += 1;
    }
  }

  const nightActivityCount = cleanEvents.filter((evt) => isNightHour(evt.created_at)).length;
  const weekendActivityCount = cleanEvents.filter((evt) => isWeekendDay(evt.created_at)).length;

  const dayCounts = Array.from(dayBuckets.values());
  const baselineBurst = Math.max(3, Math.round(Math.max(1, medianDailyEvents) * 1.8));
  const burstDays = dayCounts.filter((count) => count >= baselineBurst).length;

  const allCommits = [];
  const perRepoCommitCount = new Map();

  for (const item of Array.isArray(repoCommits) ? repoCommits : []) {
    if (!item || typeof item !== "object") continue;
    const repo = typeof item.repo === "string" ? item.repo : "unknown";
    const commits = Array.isArray(item.commits) ? item.commits.map(normalizeCommitRecord).filter(Boolean) : [];

    perRepoCommitCount.set(repo, (perRepoCommitCount.get(repo) || 0) + commits.length);

    for (const commit of commits) {
      allCommits.push(commit);
    }
  }

  const totalCommitsAnalyzed = allCommits.length;
  const topRepoCommits = Array.from(perRepoCommitCount.values()).sort((a, b) => b - a)[0] || 0;

  const messageSignals = buildCommitMessageSignals(allCommits);

  const features = {
    lookbackDays: safeNumber(lookbackDays, 45),
    accountAgeDays: safeNumber(accountAgeDays, 0),
    publicRepos: safeNumber(user && user.public_repos, 0),
    followers: safeNumber(user && user.followers, 0),
    following: safeNumber(user && user.following, 0),

    eventsAnalyzed: cleanEvents.length,
    activeDays,
    pushEvents,
    uniqueReposTouched: touchedRepos.size,
    totalCommitMentions,
    totalCommitsAnalyzed,

    nightActivityRatio: cleanEvents.length > 0 ? nightActivityCount / cleanEvents.length : 0,
    weekendActivityRatio: cleanEvents.length > 0 ? weekendActivityCount / cleanEvents.length : 0,
    burstDays,
    burstDayRatio: activeDays > 0 ? burstDays / activeDays : 0,

    dominantRepoContributionRatio:
      totalCommitsAnalyzed > 0 ? topRepoCommits / totalCommitsAnalyzed : 0,

    forcePushEventCount: forcePushEvents,
    forcePushEventRatio: pushEvents > 0 ? forcePushEvents / pushEvents : 0,

    suspiciousMessageCount: messageSignals.suspiciousMessageCount,
    suspiciousMessageRatio: messageSignals.suspiciousMessageRatio,
    shortMessageCount: messageSignals.shortMessageCount,
    shortMessageRatio: messageSignals.shortMessageRatio,
  };

  const anomalyScore = computeScore(features);
  const riskLevel = deriveRisk(anomalyScore);
  const reasons = summarizeSignals(features);

  const commitRepoBreakdown = Array.from(perRepoCommitCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([repo, count]) => ({ repo, count }));

  return {
    anomalyProfile: {
      score: anomalyScore,
      riskLevel,
      reasons,
      profileSummary: {
        accountAgeDays: features.accountAgeDays,
        eventsAnalyzed: features.eventsAnalyzed,
        activeDays: features.activeDays,
        pushEvents: features.pushEvents,
        uniqueReposTouched: features.uniqueReposTouched,
      },
      activityMetrics: {
        nightActivityRatio: Math.round(features.nightActivityRatio * 1000) / 1000,
        weekendActivityRatio: Math.round(features.weekendActivityRatio * 1000) / 1000,
        burstDays: features.burstDays,
        burstDayRatio: Math.round(features.burstDayRatio * 1000) / 1000,
      },
      contributionMetrics: {
        totalCommitsAnalyzed: features.totalCommitsAnalyzed,
        dominantRepoContributionRatio: Math.round(features.dominantRepoContributionRatio * 1000) / 1000,
        suspiciousMessageRatio: Math.round(features.suspiciousMessageRatio * 1000) / 1000,
        shortMessageRatio: Math.round(features.shortMessageRatio * 1000) / 1000,
        forcePushEventRatio: Math.round(features.forcePushEventRatio * 1000) / 1000,
      },
      topContributionRepos: commitRepoBreakdown,
      lookbackDays: features.lookbackDays,
    },
    _debug: {
      medianDailyEvents,
      baselineBurst,
      featureSnapshot: features,
    },
  };
}

module.exports = {
  analyzeUserProfileAndCommits,
};
