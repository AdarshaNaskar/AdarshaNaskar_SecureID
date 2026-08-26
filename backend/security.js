const crypto = require("crypto");
const argon2 = require("argon2");

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 15;

function validatePassword(password) {
  return (
    typeof password === "string" &&
    password.length >= MIN_PASSWORD_LENGTH &&
    password.length <= MAX_PASSWORD_LENGTH &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

/*
 * Double protection:
 * 1. Argon2id password hash
 * 2. HMAC-SHA-256 over the Argon2id encoded hash.
 *
 * The HMAC key stays server-side. This remains verifiable while
 * avoiding an uncheckable hash(hash(password)) construction.
 */
async function hashPassword(password) {
  const argonHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

  const key = getDataKey();
  const outer = crypto
    .createHmac("sha256", key)
    .update(argonHash, "utf8")
    .digest("base64url");

  return `${outer}.${argonHash}`;
}

async function verifyPassword(password, stored) {
  const dot = stored.indexOf(".");
  if (dot <= 0) return false;

  const outer = stored.slice(0, dot);
  const argonHash = stored.slice(dot + 1);

  const expectedOuter = crypto
    .createHmac("sha256", getDataKey())
    .update(argonHash, "utf8")
    .digest("base64url");

  const a = Buffer.from(outer);
  const b = Buffer.from(expectedOuter);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  return argon2.verify(argonHash, password);
}

function getDataKey() {
  const raw = process.env.DATA_KEY;
  if (!raw) throw new Error("DATA_KEY is not configured");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) throw new Error("DATA_KEY must decode to 32 bytes");
  return key;
}

function encryptSecret(value) {
  const key = getDataKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    iv.toString("base64url"),
    tag.toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

function decryptSecret(value) {
  const [ivPart, tagPart, dataPart] = value.split(".");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getDataKey(),
    Buffer.from(ivPart, "base64url"),
  );

  decipher.setAuthTag(Buffer.from(tagPart, "base64url"));

  return Buffer.concat([
    decipher.update(Buffer.from(dataPart, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

module.exports = {
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  validatePassword,
  hashPassword,
  verifyPassword,
  encryptSecret,
  decryptSecret,
};
