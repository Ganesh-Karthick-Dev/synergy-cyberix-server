import { Router } from 'express';
import { body } from 'express-validator';
import { UserController } from '../modules/controllers/user.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/validation.middleware';

const router = Router();
const userController = new UserController();

// Validation rules
const updateProfileValidation = [
  body('email').optional().isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('username').optional().isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must be 3-20 characters and contain only letters, numbers, and underscores'),
  body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
];

const changePasswordValidation = [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
];

// Routes
router.get('/profile', authenticate, userController.getProfile.bind(userController));
router.put('/profile', authenticate, validate(updateProfileValidation), userController.updateProfile.bind(userController));
router.put('/change-password', authenticate, validate(changePasswordValidation), userController.changePassword.bind(userController));
router.delete('/account', authenticate, userController.deleteAccount.bind(userController));

// Admin routes
router.get('/', authenticate, authorize('ADMIN'), userController.getAllUsers.bind(userController));
router.get('/:id', authenticate, authorize('ADMIN'), userController.getUserById.bind(userController));

export { router as userRoutes };
