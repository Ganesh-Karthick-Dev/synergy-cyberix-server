import { Router } from 'express';
import { authRoutes } from './auth.routes';
import { userRoutes } from './user.routes';

const router = Router();

// API Documentation endpoint
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Cyberix API Server',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      users: '/api/users'
    },
    documentation: {
      health: '/health',
      api: '/api'
    }
  });
});

// Route modules
router.use('/auth', authRoutes);
router.use('/users', userRoutes);

export { router as apiRoutes };
