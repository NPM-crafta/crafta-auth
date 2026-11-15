# Adaptive Testing & Logging (Developer Guide)

This is a lightweight, developer-friendly testing + logging skeleton you can extend.

## Files (shipped with `src/` for publish)
- `dev-tools/logger.js` — colored terminal logging (`SUCCESS`, `WARN`, `FAIL`, `SKIP`, `INFO`).
- `dev-tools/feature-config.js` — sample feature toggles + auth config.
- `dev-tools/smoke-tests/*.js` — smoke tests for all features (exports, flags, middleware, passwords, MFA, audit, new features).
- `dev-tools/smoke-tests/run-smoke-tests.js` — runs all smoke tests.

## Library exports (for consumers)
- `runAdaptiveTests(config, featureFlags?, opts?)`
- `inferFeatureFlags(config)`
- `testCatalog` (for extension)
- `getPasswordStrength(password)` — NEW: returns score 0-4

## Run smoke tests
```bash
npm test
```

or run individual tests:
```bash
node dev-tools/smoke-tests/run-smoke-tests.js
```

## Feature Flags
All features can be enabled/disabled via the `features` config:

```javascript
auth({
  features: {
    emailVerification: true,
    twoFactor: true,
    passwordless: false,
    webhooks: false,
    rateLimit: true,
    auditLogs: true,
    csrf: false,
    socialAccountLinking: true,      // NEW
    sessionManagement: true,          // NEW
    passwordStrengthMeter: true       // NEW
  }
})(app);
```

## New Features (v2.2.0)

### Social Account Linking
Link social providers to existing password accounts:
```javascript
await app.authService.linkSocialAccount(userId, 'google', 'google-provider-id');
await app.authService.unlinkSocialAccount(userId, 'google');
```

### Device Trust
Trust devices to skip 2FA requirements:
```javascript
await app.sessionService.trustDevice(user, deviceId, userAgent, ip, ttlDays);
console.log(user.isDeviceTrusted(deviceId)); // true
```

### Password Strength Meter
Get real-time password strength feedback:
```javascript
// API: GET /password-strength?password=mypassword
// Returns: { success: true, score: 2, strength: "fair" }
```

### Session Management
Manage user sessions:
```javascript
await app.sessionService.listSessions(user);
await app.sessionService.revokeSession(user, sessionId);
await app.sessionService.revokeAllSessions(user);
```

## How it works
- Feature flags live in `features` object in config.
- The runner reads the flags and only executes tests whose `feature` matches an enabled flag.
- Config changes require no test edits; toggling a flag updates which tests run.
- Add new features by adding a flag in `features` and a test entry.

## Integrating with the auth library
- `dev-tools/example-app.js` shows how to load your library (`auth(cfg)(app)`) and print startup messages reflecting enabled features.
- Wire real tests by replacing the mock test bodies with actual calls to your services/routes.

## Extending
- Add more feature keys and corresponding tests.
- Point `feature-config.js` at your real project config or load from env for true parity.
