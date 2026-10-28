// packages/auth/src/utils/api-error.js
/**
 * Standardized, machine-readable auth errors.
 *
 * Every error thrown by the library carries:
 *   - code    : stable, namespaced error code (AUTH_*)
 *   - message : human-readable description
 *   - status  : HTTP status code
 *   - details : optional structured payload (e.g. field-level messages)
 *
 * Frontends can switch on `code` instead of parsing prose strings.
 */
class ApiError extends Error {
  constructor(message, code = 'AUTH_INTERNAL', status = 400, details = undefined) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    if (details !== undefined) this.details = details;

    // keep V8 stack trace behaviour intact
    Error.captureStackTrace(this, this.constructor);
  }

  // ---- factory helpers -------------------------------------------------
  static unauthorized(message = 'Authentication required', details) {
    return new ApiError(message, 'AUTH_UNAUTHORIZED', 401, details);
  }

  static forbidden(message = 'Insufficient permissions', details) {
    return new ApiError(message, 'AUTH_FORBIDDEN', 403, details);
  }

  static notFound(message = 'Resource not found', details) {
    return new ApiError(message, 'AUTH_NOT_FOUND', 404, details);
  }

  static validation(message = 'Invalid request data', details) {
    return new ApiError(message, 'AUTH_VALIDATION', 400, details);
  }

  static badRequest(message = 'Bad request', details) {
    return new ApiError(message, 'AUTH_BAD_REQUEST', 400, details);
  }

  static conflict(message = 'Resource already exists', details) {
    return new ApiError(message, 'AUTH_CONFLICT', 409, details);
  }

  static tooManyRequests(message = 'Too many requests, please try later', details) {
    return new ApiError(message, 'AUTH_RATE_LIMITED', 429, details);
  }

  static accountLocked(message = 'Account locked. Try again later.', details) {
    return new ApiError(message, 'AUTH_ACCOUNT_LOCKED', 403, details);
  }

  static invalidCredentials(message = 'Invalid credentials', details) {
    return new ApiError(message, 'AUTH_INVALID_CREDENTIALS', 401, details);
  }

  static invalidToken(message = 'Invalid or expired token', details) {
    return new ApiError(message, 'AUTH_INVALID_TOKEN', 401, details);
  }

  static expiredToken(message = 'Token expired', details) {
    return new ApiError(message, 'AUTH_EXPIRED_TOKEN', 401, details);
  }

  static emailNotVerified(message = 'Email not verified', details) {
    return new ApiError(message, 'AUTH_EMAIL_NOT_VERIFIED', 403, details);
  }

  static twoFactorRequired(message = 'Two-factor authentication required', details) {
    return new ApiError(message, 'AUTH_2FA_REQUIRED', 403, details);
  }

  static twoFactorFailed(message = 'Invalid 2FA code', details) {
    return new ApiError(message, 'AUTH_2FA_FAILED', 401, details);
  }

  static passwordPolicy(message = 'Password policy violation', details) {
    return new ApiError(message, 'AUTH_PASSWORD_POLICY', 400, details);
  }

  static passwordReuse(message = 'Cannot reuse previous passwords', details) {
    return new ApiError(message, 'AUTH_PASSWORD_REUSE', 400, details);
  }

  static smtpDisabled(message = 'Email delivery is not configured', details) {
    return new ApiError(message, 'AUTH_SMTP_DISABLED', 503, details);
  }

  static socialAuthFailed(message = 'Social login failed', details) {
    return new ApiError(message, 'AUTH_SOCIAL_FAILED', 400, details);
  }

  static internal(message = 'Internal server error', details) {
    return new ApiError(message, 'AUTH_INTERNAL', 500, details);
  }

  // ---- predicates -------------------------------------------------------
  /** true when the thrown value is one of our ApiError instances */
  static isApiError(err) {
    return err instanceof ApiError;
  }

  /** Coerce any thrown value into an ApiError (never throws) */
  static normalize(err) {
    if (err instanceof ApiError) return err;

    if (err && typeof err === 'object') {
      // mongoose ValidationError
      if (err.name === 'ValidationError') {
        const details = {};
        for (const [k, v] of Object.entries(err.errors || {})) {
          details[k] = v.message;
        }
        return new ApiError(
          'Validation failed',
          'AUTH_VALIDATION',
          400,
          Object.keys(details).length ? details : undefined
        );
      }
      // jwt errors
      if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        return new ApiError(
          err.message || 'Invalid token',
          err.name === 'TokenExpiredError' ? 'AUTH_EXPIRED_TOKEN' : 'AUTH_INVALID_TOKEN',
          401
        );
      }
      // CastError (invalid ObjectId etc.)
      if (err.name === 'CastError') {
        return new ApiError('Invalid identifier', 'AUTH_INVALID_ID', 400);
      }
      // duplicate key
      if (err.code === 11000) {
        const field = err.keyValue ? Object.keys(err.keyValue)[0] : 'field';
        return new ApiError(
          `${field} already exists`,
          'AUTH_CONFLICT',
          409,
          { field }
        );
      }
      if (typeof err.status === 'number') {
        return new ApiError(
          err.message || 'Request failed',
          err.code || 'AUTH_EXTERNAL',
          err.status
        );
      }
    }

    if (err instanceof Error) {
      return new ApiError(err.message, 'AUTH_INTERNAL', 500);
    }

    return new ApiError('Internal server error', 'AUTH_INTERNAL', 500);
  }
}

module.exports = ApiError;