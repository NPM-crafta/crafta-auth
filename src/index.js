const express = require('express');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require("helmet");
const mongoose = require("mongoose");   // <<< FIX ADDED

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const AuthService = require('./services/auth.service');
const RoleService = require('./services/role.service');
const AuditService = require('./services/audit.service');
const MFAService = require('./utils/mfa');
const PasswordPolicy = require('./utils/password-policy');
const createAuthMiddleware = require('./middlewares/auth.middleware');
const validators = require('./middlewares/validation.middleware');


const defaultConfig = {
  strategy: 'jwt',
  fields: ['email', 'password'],
  routes: {
    register: '/register',
    login: '/login',
    verify: '/verify',
    forgotPassword: '/forgot-password',
    resetPassword: '/reset-password',
    refreshToken: '/refresh-token',
    profile: '/profile',
    twoFactor: '/2fa',
    roles: '/roles',
    permissions: '/permissions'
  },
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/forge-auth',
  maxLoginAttempts: 5,
  emailVerification: true,
  loginAlerts: true,
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    expiryDays: 90
  },
  smtp: null,
  social: {
    google: null,
    facebook: null,
    github: null
  },
  env: {
    JWT_SECRET: process.env.JWT_SECRET
  },
  accessTokenExpiry: '1h',
  refreshTokenDays: 7
};

// minimal ApiError re-export if needed
class ApiError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function auth(config = {}) {
  const finalConfig = { ...defaultConfig, ...config };
  finalConfig.env = { ...(defaultConfig.env || {}), ...(config.env || process.env) };

  if (!finalConfig.env?.JWT_SECRET) {
    throw new Error('JWT_SECRET is required in environment configuration');
  }

  if (finalConfig.emailVerification && !finalConfig.smtp) {
    throw new Error('SMTP configuration is required for email verification');
  }

  // ------------------------------------------
  // ✅ FIX — Proper MongoDB Connection
  // ------------------------------------------
  if (mongoose.connection.readyState === 0) {
    mongoose.connect(finalConfig.mongoUrl, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    })
      .then(() => console.log("📦 Auth Library MongoDB Connected"))
      .catch(err => console.error("❌ Auth Library MongoDB Error:", err));
  } else {
    console.log("📦 Using existing mongoose connection");
  }
  // ------------------------------------------

  const authService = new AuthService(finalConfig);
  const roleService = new RoleService();
  const auditService = new AuditService();
  const mfaService = new MFAService();
  const passwordPolicy = new PasswordPolicy(finalConfig.passwordPolicy);
  const { rateLimiter, limiterFor, verifyToken, checkRole, checkOwnershipOrAdmin } = createAuthMiddleware(finalConfig);

  if (finalConfig.social && finalConfig.social.google) {
    passport.use(new GoogleStrategy(finalConfig.social.google,
      async (accessToken, refreshToken, profile, done) => {
        try {
          const user = await authService.handleSocialLogin('google', profile);
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    ));
  }

  return function (app) {
    app.use(cookieParser());

    if (finalConfig.enableCSRF) {
      const csrfProtection = csrf({ cookie: true });
      app.use(csrfProtection);

      app.get('/csrf-token', (req, res) => {
        res.json({ csrfToken: req.csrfToken() });
      });
    }

    app.use(passport.initialize());
    app.use(rateLimiter);
    app.use(helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    }));

    app.authService = authService;
    app.roleService = roleService;
    app.auditService = auditService;
    app.mfaService = mfaService;
    app.passwordPolicy = passwordPolicy;

    // REGISTER
    app.post(
      finalConfig.routes.register,
      limiterFor('register'),
      validators.registerValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const { isValid, errors } = passwordPolicy.validate(req.body.password, {
            email: req.body.email,
            name: req.body.name
          });

          if (!isValid) {
            return res.status(400).json({ success: false, error: 'Password policy violation', details: errors });
          }

          const user = await authService.register(req.body);
          await auditService.logActivity({
            userId: user._id,
            action: 'register',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
          });

          res.status(201).json({ success: true, message: 'Registration successful' });
        } catch (err) {
          next(err);
        }
      }
    );

    // LOGIN
    app.post(
      finalConfig.routes.login,
      limiterFor('login'),
      validators.loginValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const deviceInfo = { browser: req.headers['user-agent'], ip: req.ip };
          const result = await authService.login(req.body.email, req.body.password, deviceInfo);

          await auditService.logActivity({
            userId: result.user?._id,
            action: 'login',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
          });

          res.json({ success: true, ...result });
        } catch (err) {
          await auditService.logActivity({
            action: 'login',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'failure',
            details: { error: err.message }
          });
          next(err);
        }
      }
    );

    // 2FA
    app.post(
      finalConfig.routes.twoFactor,
      limiterFor('2fa'),
      validators.twoFAValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const result = await authService.verify2FA(req.body.userId, req.body.code);
          await auditService.logActivity({ userId: result.user._id, action: '2fa_verify', status: 'success' });
          res.json({ success: true, ...result });
        } catch (err) {
          next(err);
        }
      }
    );

    // FORGOT PASSWORD
    app.post(
      finalConfig.routes.forgotPassword,
      limiterFor('forgotPassword'),
      validators.forgotPasswordValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          await authService.forgotPassword(req.body.email);
          res.json({ success: true, message: 'Password reset email sent if user exists' });
        } catch (err) {
          next(err);
        }
      }
    );

    // RESET PASSWORD
    app.post(
      finalConfig.routes.resetPassword,
      validators.resetPasswordValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          await authService.resetPassword(req.body.token, req.body.newPassword);
          await auditService.logActivity({ action: 'password_reset', status: 'success' });
          res.json({ success: true, message: 'Password reset successful' });
        } catch (err) {
          next(err);
        }
      }
    );

    // REFRESH TOKEN
    app.post(
      finalConfig.routes.refreshToken,
      validators.refreshTokenValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const result = await authService.refreshToken(req.body.refreshToken);
          res.json({ success: true, ...result });
        } catch (err) {
          next(err);
        }
      }
    );

    // UPDATE PROFILE
    app.put(
      finalConfig.routes.profile,
      verifyToken,
      checkOwnershipOrAdmin((req) => req.user.id),
      validators.profileUpdateValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const user = await authService.updateProfile(req.user.id, req.body);
          await auditService.logActivity({ userId: user._id, action: 'profile_update', status: 'success' });
          res.json({ success: true, user });
        } catch (err) {
          next(err);
        }
      }
    );

    // CREATE ROLE (ADMIN)
    app.post('/roles', verifyToken, checkRole(['admin']), async (req, res, next) => {
      try {
        const role = await roleService.createRole(req.body);
        res.status(201).json({ success: true, role });
      } catch (err) {
        next(err);
      }
    });

    // GOOGLE OAUTH
    if (finalConfig.social && finalConfig.social.google) {
      app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

      app.get('/auth/google/callback',
        passport.authenticate('google', { session: false }),
        async (req, res, next) => {
          try {
            const tokens = await authService.generateTokens(req.user);
            await auditService.logActivity({
              userId: req.user._id,
              action: 'social_login',
              status: 'success',
              details: { provider: 'google' }
            });
            res.json({ success: true, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: req.user });
          } catch (err) {
            next(err);
          }
        });
    }

    // ERROR HANDLER
    app.use((err, req, res, next) => {
      console.error(err && err.stack ? err.stack : err);
      const status = err.status || (err.name === 'ValidationError' ? 400 : 500);

      let message;
      if (status >= 400 && status < 500) {
        message = err.message || 'Bad request';
      } else {
        message = process.env.NODE_ENV === 'development'
          ? (err.message || 'Internal Server Error')
          : 'Internal Server Error';
      }

      res.status(status).json({ success: false, error: message });
    });
  };
}

module.exports = { auth, ApiError };