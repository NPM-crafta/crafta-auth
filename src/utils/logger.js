// Lightweight terminal logger with colorized prefixes.
const COLORS = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

const prefix = {
  success: `${COLORS.green}[SUCCESS]${COLORS.reset}`,
  info: `${COLORS.cyan}[INFO]${COLORS.reset}`,
  warn: `${COLORS.yellow}[WARN]${COLORS.reset}`,
  error: `${COLORS.red}[FAIL]${COLORS.reset}`,
  skip: `${COLORS.gray}[SKIP]${COLORS.reset}`
};

function maybeLog(enabled, fn) {
  return (msg) => {
    if (enabled === false) return;
    fn(msg);
  };
}

function createLogger(enabled = true) {
  return {
    logSuccess: maybeLog(enabled, (msg) => console.log(`${prefix.success} ${msg}`)),
    logInfo: maybeLog(enabled, (msg) => console.log(`${prefix.info} ${msg}`)),
    logWarn: maybeLog(enabled, (msg) => console.warn(`${prefix.warn} ${msg}`)),
    logError: maybeLog(enabled, (msg) => console.error(`${prefix.error} ${msg}`)),
    logSkip: maybeLog(enabled, (msg) => console.log(`${prefix.skip} ${msg}`))
  };
}

module.exports = {
  createLogger
};
