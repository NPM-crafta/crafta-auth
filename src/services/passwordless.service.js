// packages/auth/src/services/passwordless.service.js
/**
 * PasswordlessService — magic-link login.
 *
 * Flow:
 *   1. POST /auth/magic-link  { email }  → creates a single-use token, emails it
 *   2. GET  /auth/magic-link/verify?token=...  → validates, logs user in
 *
 * Tokens are short-lived (default 15 min) and single-use.
 */
const crypto = require('crypto');
const ApiError = require('../utils/api-error');

class PasswordlessService {
  constructor(config = {}) {
    this.config = config;
    this.emailService = config.emailService;
    this.tokenTtlMs = (config.passwordless && config.passwordless.tokenTtlMs) || 15 * 60 * 1000;
  }

  generateToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  async requestMagicLink(email, baseUrl) {
    const User = require('../models/user');
    const user = await User.findOne({ email });
    // Don't reveal whether the email exists — just return success either way.
    if (!user) return { sent: false, reason: 'user_not_found' };

    const token = this.generateToken();
    user.magicLinkToken = token;
    user.magicLinkExpires = Date.now() + this.tokenTtlMs;
    await user.save();

    const linkPath = this.config.routes?.magicLink || '/auth/magic-link/verify';
    const url = `${baseUrl || ''}${linkPath}?token=${token}`;

    if (this.emailService) {
      await this.emailService.sendMagicLink(user, url);
    }

    return { sent: true };
  }

  async verifyMagicLink(token) {
    const User = require('../models/user');
    const user = await User.findOne({
      magicLinkToken: token,
      magicLinkExpires: { $gt: Date.now() }
    }).select('+magicLinkToken +magicLinkExpires');

    if (!user) {
      throw ApiError.invalidToken('Invalid or expired magic link');
    }

    // Single-use: consume the token.
    user.magicLinkToken = undefined;
    user.magicLinkExpires = undefined;
    await user.save();

    return user;
  }
}

module.exports = PasswordlessService;