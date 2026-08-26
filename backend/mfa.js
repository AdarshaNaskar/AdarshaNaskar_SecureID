const { generateSecret, generateURI, verify } = require("otplib");

const QRCode = require("qrcode");

const { encryptSecret, decryptSecret } = require("./security");

/*
 * Create authenticator setup
 *
 * Generates a Base32 secret and the otpauth URI
 * used by Google Authenticator / Authy.
 */
function createAuthenticatorSetup(email) {
  const secret = generateSecret(20);

  const otpauth = generateURI({
    issuer: "SecureID",
    label: email,
    secret,
  });

  return {
    secret,
    otpauth,
  };
}

/*
 * Generate QR code from the otpauth URI.
 */
async function createQrCode(otpauth) {
  return QRCode.toDataURL(otpauth, {
    errorCorrectionLevel: "M",
    margin: 2,
    width: 220,
  });
}

/*
 * Verify authenticator code.
 *
 * otplib v13 returns an object:
 *
 * {
 *   valid: true/false
 * }
 */
async function verifyTotp(secret, code) {
  const result = await verify({
    secret,
    token: code,
  });

  return result.valid === true;
}

/*
 * Encrypt the TOTP secret before storing it.
 */
function protectSecret(secret) {
  return encryptSecret(secret);
}

/*
 * Decrypt the TOTP secret when verifying.
 */
function revealSecret(protectedSecret) {
  return decryptSecret(protectedSecret);
}

module.exports = {
  createAuthenticatorSetup,
  createQrCode,
  verifyTotp,
  protectSecret,
  revealSecret,
};
