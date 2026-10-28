// packages/auth/src/middlewares/cors.middleware.js
/**
 * CORS middleware — explicit origin whitelist instead of the default
 * "reflect any origin" behaviour, which is a security risk for auth APIs.
 *
 * If `config.cors` is omitted, we default to a safe deny-everything policy
 * for auth routes (they should be consumed by a trusted frontend).
 */
const ApiError = require('../utils/api-error');

const DEFAULT_CORS = {
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
  maxAge: 86400
};

function normalizeOrigin(origin) {
  if (!origin) return null;
  try {
    const u = new URL(origin);
    return `${u.protocol}//${u.host}`;
  } catch {
    return origin;
  }
}

function corsMiddleware(config = {}) {
  const cors = { ...DEFAULT_CORS, ...(config.cors || {}) };

  // Build the set of allowed origins once.
  const allowed = Array.isArray(cors.origin)
    ? cors.origin.map(normalizeOrigin)
    : cors.origin === '*'
      ? null // null means "reflect any" (explicit opt-in)
      : [normalizeOrigin(cors.origin)];

  return (req, res, next) => {
    const requestOrigin = req.headers.origin;

    // Always set safe headers for preflight.
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', cors.methods.join(','));
      res.setHeader('Access-Control-Allow-Headers', cors.allowedHeaders.join(','));
      res.setHeader('Access-Control-Max-Age', String(cors.maxAge));
      if (cors.credentials) res.setHeader('Access-Control-Allow-Credentials', 'true');
      if (allowed === null) {
        if (requestOrigin) res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      } else if (allowed.includes(normalizeOrigin(requestOrigin))) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      }
      return res.status(204).end();
    }

    // Actual request.
    if (allowed === null) {
      // Reflect any — only safe when the app explicitly opts in.
      if (requestOrigin) res.setHeader('Access-Control-Allow-Origin', requestOrigin);
    } else if (requestOrigin && allowed.includes(normalizeOrigin(requestOrigin))) {
      res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      res.setHeader('Access-Control-Allow-Credentials', String(cors.credentials));
    } else if (requestOrigin) {
      // Origin not in whitelist — block it.
      return next(ApiError.forbidden('Origin not allowed by CORS policy'));
    }

    if (cors.credentials) res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
  };
}

module.exports = corsMiddleware;