const Redis = require("ioredis");

let redisClient = null;
let redisInitAttempted = false;

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function getRedisClient() {
  if (redisClient) return redisClient;
  if (redisInitAttempted) return null;

  redisInitAttempted = true;

  const uri = process.env.REDIS_URI;
  if (!isNonEmptyString(uri)) {
    return null;
  }

  const client = new Redis(uri.trim(), {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableReadyCheck: true,
  });

  client.on("error", () => {
    // Swallow noisy errors; callers should treat Redis as best-effort.
  });

  redisClient = client;
  return redisClient;
}

async function ensureConnected(client) {
  if (!client) return;
  if (client.status === "ready") return;
  if (client.status === "connecting") return;

  await client.connect();
}

async function redisGetJson(key) {
  const client = getRedisClient();
  if (!client) return null;

  try {
    await ensureConnected(client);
    const raw = await client.get(key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function redisSetJson(key, value, ttlSeconds) {
  const client = getRedisClient();
  if (!client) return false;

  const ttl = typeof ttlSeconds === "number" && Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : null;

  try {
    await ensureConnected(client);
    const payload = JSON.stringify(value);

    if (ttl) {
      await client.set(key, payload, "EX", Math.floor(ttl));
    } else {
      await client.set(key, payload);
    }

    return true;
  } catch {
    return false;
  }
}

module.exports = {
  getRedisClient,
  redisGetJson,
  redisSetJson,
};
