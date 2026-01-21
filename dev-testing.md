# Adaptive Testing & Logging (Developer Guide)

This is a lightweight, developer-friendly testing + logging skeleton you can extend.

## Files (shipped with `src/` for publish)
- `dev-tools/logger.js` — colored terminal logging (`SUCCESS`, `WARN`, `FAIL`, `SKIP`, `INFO`).
- `dev-tools/feature-config.js` — sample feature toggles + auth config.
- `dev-tools/tests.js` — mock feature tests (JWT, Email OTP, OAuth, 2FA) tagged by feature key.
- `dev-tools/run-tests.js` — adaptive runner that executes only enabled-feature tests.
- `dev-tools/example-app.js` — minimal Express wiring showing startup logs and honoring feature flags.

## Library exports (for consumers)
- `runAdaptiveTests(config, featureFlags?, opts?)`
- `inferFeatureFlags(config)`
- `testCatalog` (for extension)

## Run adaptive tests
```bash
node dev-tools/run-tests.js
```

Sample output
```
[INFO] Adaptive test runner starting…
[INFO] JWT secret present, token signing would proceed
[SUCCESS] JWT issues token
[INFO] SMTP host: smtp.example.com
[SUCCESS] Email OTP sends message
[SKIP] OAuth login flow - feature disabled
[INFO] 2FA code verification simulated
[SUCCESS] 2FA TOTP validation
[SUCCESS] Adaptive tests complete.
```

## How it works
- Feature flags live in `feature-config.js` (`features.jwt`, `features.emailOtp`, `features.oauth`, `features.twofa`).
- The runner reads the flags and only executes tests whose `feature` matches an enabled flag.
- Config changes require no test edits; toggling a flag updates which tests run.
- Add new features by adding a flag in `feature-config.js` and a test entry in `tests.js`.

## Integrating with the auth library
- `dev-tools/example-app.js` shows how to load your library (`auth(cfg)(app)`) and print startup messages reflecting enabled features.
- Wire real tests by replacing the mock test bodies in `tests.js` with actual calls to your services/routes.

## Extending
- Add more log helpers in `logger.js` if you want structured output.
- Add more feature keys (e.g., `emailVerification`, `refreshTokens`) and corresponding tests.
- Point `feature-config.js` at your real project config or load from env for true parity.
