import { Router } from 'express';
import { body } from 'express-validator';
import { AuthController } from '../modules/controllers/auth.controller';
import { validate } from '../middlewares/validation.middleware';

const router = Router();
const authController = new AuthController();

// Validation rules for registration
const registerUserValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid organization email'),
  body('firstName').isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters'),
  body('lastName').isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters'),
  body('phone').matches(/^[\+]?[1-9][\d]{0,15}$/).withMessage('Please provide a valid phone number'),
  body('subscriptionType').optional().isIn(['FREE', 'PRO', 'PRO_PLUS']).withMessage('Subscription type must be FREE, PRO, or PRO_PLUS')
];

// API Documentation endpoint
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Cyberix Security API Server',
    version: '1.0.0',
    endpoints: {
      register: 'POST /api/register',
      health: 'GET /health'
    },
    description: 'Cybersecurity platform with user registration and management'
  });
});

// Registration endpoint
router.post('/register', validate(registerUserValidation), authController.registerUser.bind(authController));

export { router as apiRoutes };
