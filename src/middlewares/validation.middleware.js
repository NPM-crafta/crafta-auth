// packages/auth/src/middlewares/validation.middleware.js
const { body, param, validationResult } = require('express-validator');

// validators
const registerValidator = [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/\d/).withMessage('Password must contain a number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain a special character'),
  body('name').optional().isString().trim().isLength({ min: 2 }).withMessage('Name too short')
];

const loginValidator = [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').exists().withMessage('Password is required')
];

const forgotPasswordValidator = [
  body('email').isEmail().withMessage('Valid email is required')
];

const resetPasswordValidator = [
  body('token').exists().withMessage('Reset token required'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/\d/).withMessage('Password must contain a number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain a special character')
];

const twoFAValidator = [
  body('userId').exists().withMessage('userId required'),
  body('code').isLength({ min: 4 }).withMessage('Invalid 2FA code')
];

const refreshTokenValidator = [
  body('refreshToken').exists().withMessage('refreshToken required')
];

const profileUpdateValidator = [
  body().custom((value, { req }) => {
    // prevent sensitive fields in payload
    const forbidden = ['password', 'role', 'refreshTokens', 'isVerified', 'verificationToken', 'twoFactorSecret', '_id'];
    for (const f of forbidden) {
      if (req.body.hasOwnProperty(f)) {
        throw new Error(`Cannot update field: ${f}`);
      }
    }
    return true;
  })
];

// handler to send friendly validation errors
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();

  const payload = errors.array().map(e => ({ field: e.param, msg: e.msg }));
  return res.status(400).json({
    success: false,
    error: 'Invalid request data',
    details: payload
  });
};

module.exports = {
  registerValidator,
  loginValidator,
  forgotPasswordValidator,
  resetPasswordValidator,
  twoFAValidator,
  refreshTokenValidator,
  profileUpdateValidator,
  handleValidation
};
