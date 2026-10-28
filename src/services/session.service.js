// packages/auth/src/services/session.service.js
/**
 * SessionService — manages user sessions with a global "session version"
 * stamp so that a password change, admin action, or logout-all can invalidate
 * every existing JWT issued before the event.
 *
 * This is the backbone of true "log out everywhere" behaviour.
 */
const ApiError = require('../utils/api-error');

class SessionService {
  constructor(config = {}) {
    this.config = config;
    this.maxSessions = (config.session && config.session.maxSessions) || 5;
    this.sessionExpiryMs =
      (config.session && config.session.sessionExpiryMs) || 30 * 24 * 60 * 60 * 1000; // 30d
  }

  /**
   * Bump the user's session version. Every existing JWT issued before this
   * moment becomes invalid.
   */
  async bumpSessionVersion(user) {
    user.sessionVersion = (user.sessionVersion || 0) + 1;
    await user.save();
    return user.sessionVersion;
  }

  /**
   * Enforce per-user session cap. If the user has more active sessions than
   * `maxSessions`, drop the oldest ones.
   */
  async enforceSessionCap(user) {
    const sessions = user.sessions || [];
    if (sessions.length <= this.maxSessions) return;

    // sort oldest-first by createdAt
    sessions.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    const toRemove = sessions.length - this.maxSessions;
    sessions.splice(0, toRemove);
    user.sessions = sessions;
    await user.save();
  }

  /**
   * Validate that a decoded JWT's sessionVersion matches the user's current
   * version. If not, the session has been revoked globally.
   */
  validateSession(decoded, user) {
    const tokenVersion = decoded.sessionVersion || 0;
    const currentVersion = user.sessionVersion || 0;
    if (tokenVersion !== currentVersion) {
      throw ApiError.unauthorized(
        'Session has been invalidated. Please log in again.'
      );
    }
    return true;
  }

  /**
   * Create a new session record for a user (used during login / social login).
   */
  async createSession(user, info = {}) {
    const crypto = require('crypto');
    const session = {
      sessionId: crypto.randomBytes(16).toString('hex'),
      userAgent: info.userAgent || 'unknown',
      ip: info.ip || 'unknown',
      createdAt: new Date()
    };
    user.sessions = user.sessions || [];
    user.sessions.push(session);
    await this.enforceSessionCap(user);
    return session;
  }

  /**
   * Revoke a single session by sessionId.
   */
  async revokeSession(user, sessionId) {
    if (!user.sessions) return;
    user.sessions = user.sessions.filter((s) => s.sessionId !== sessionId);
    await user.save();
  }

  /**
   * Revoke ALL sessions for a user (logout everywhere).
   */
  async revokeAllSessions(user) {
    user.sessions = [];
    await this.save(user);
    return this.bumpSessionVersion(user);
  }

  async save(user) {
    await user.save();
  }
}

module.exports = SessionService;