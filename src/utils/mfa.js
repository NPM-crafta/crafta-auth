// packages/auth/src/utils/mfa.js
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const ApiError = require('./api-error');

class MFAService {
  async generateSecret(label, issuer = 'App') {
    try {
      const secret = speakeasy.generateSecret({
        length: 32,
        name: label,
        issuer
      });

      const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

      return {
        secret: secret.base32,
        qrCode: qrCodeUrl
      };
    } catch (err) {
      throw ApiError.internal('Failed to generate MFA secret');
    }
  }

  verifyToken(token, secret) {
    try {
      return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1
      });
    } catch (err) {
      return false;
    }
  }

  // Generate hashed backup codes (safer)
  generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      const raw = crypto.randomBytes(10).toString('hex');
      const hash = crypto.createHash('sha256').update(raw).digest('hex');

      codes.push({
        raw,       // show raw one time only
        hash       // stored version
      });
    }
    return codes;
  }

  verifyBackupCode(rawCode, storedCodes = []) {
    const rawHash = crypto.createHash('sha256').update(rawCode).digest('hex');
    return storedCodes.find(c => c.hash === rawHash);
  }
}

module.exports = MFAService;
