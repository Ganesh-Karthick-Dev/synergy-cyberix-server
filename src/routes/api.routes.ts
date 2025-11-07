import { Router } from 'express';
import { RegistrationController } from '../modules/controllers/registration.controller';

const router = Router();
const registrationController = new RegistrationController();

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

// Registration endpoint - Note: This route is also handled by decorators via RouteFactory
// Keeping this for backward compatibility, but the decorator-based route should be used
router.post('/register', registrationController.registerUser.bind(registrationController));

export { router as apiRoutes };
