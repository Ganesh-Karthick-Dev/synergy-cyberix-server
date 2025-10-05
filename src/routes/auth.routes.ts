import { Router } from 'express';
import { body } from 'express-validator';
import { AuthController } from '../modules/controllers/auth.controller';
import { authenticate, optionalAuth } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/validation.middleware';

const router = Router();
const authController = new AuthController();

// Validation rules
const registerValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('username').isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must be 3-20 characters and contain only letters, numbers, and underscores'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('firstName').optional().isLength({ max: 50 }).withMessage('First name must not exceed 50 characters'),
  body('lastName').optional().isLength({ max: 50 }).withMessage('Last name must not exceed 50 characters'),
  body('phone').optional().isString().withMessage('Phone must be a string')
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
  body('deviceInfo').optional().isString().withMessage('Device info must be a string'),
  body('rememberMe').optional().isBoolean().withMessage('Remember me must be a boolean')
];

const refreshTokenValidation = [
  body('refreshToken').notEmpty().withMessage('Refresh token is required')
];

const forgotPasswordValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email')
];

const resetPasswordValidation = [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
];

// Routes
router.post('/register', validate(registerValidation), authController.register.bind(authController));
router.post('/login', validate(loginValidation), authController.login.bind(authController));
router.post('/refresh-token', validate(refreshTokenValidation), authController.refreshToken.bind(authController));
router.post('/logout', authenticate, authController.logout.bind(authController));
router.get('/profile', authenticate, authController.getProfile.bind(authController));

// Session management
router.get('/sessions', authenticate, authController.getActiveSessions.bind(authController));
router.delete('/sessions/:sessionId', authenticate, authController.revokeSession.bind(authController));
router.delete('/sessions', authenticate, authController.revokeAllSessions.bind(authController));

// Password management
router.post('/forgot-password', validate(forgotPasswordValidation), authController.forgotPassword.bind(authController));
router.post('/reset-password', validate(resetPasswordValidation), authController.resetPassword.bind(authController));

export { router as authRoutes };
