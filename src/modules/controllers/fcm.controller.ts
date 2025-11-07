import { Request, Response } from 'express';
import { Controller, Post, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { FirebaseService } from '../services/firebase.service';
import { authenticate } from '../../middlewares/auth.middleware';

@Service()
@Controller('/api/fcm')
export class FcmController {
  @Post('/token')
  @Validate([
    body('fcmToken').notEmpty().withMessage('FCM token is required'),
  ])
  async storeToken(req: Request, res: Response): Promise<void> {
    try {
      const { fcmToken } = req.body;
      const userId = req.user!.id;

      const firebaseService = new FirebaseService();

      await firebaseService.storeFcmToken(userId, fcmToken, {
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip,
        deviceInfo: req.get('User-Agent'),
      });

      const response: ApiResponse = {
        success: true,
        message: 'FCM token stored successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to store FCM token',
          statusCode: 500
        }
      });
    }
  }

  @Delete('/token')
  @Validate([
    body('fcmToken').notEmpty().withMessage('FCM token is required'),
  ])
  async removeToken(req: Request, res: Response): Promise<void> {
    try {
      const { fcmToken } = req.body;
      const userId = req.user!.id;

      const firebaseService = new FirebaseService();
      await firebaseService.removeFcmToken(userId, fcmToken);

      const response: ApiResponse = {
        success: true,
        message: 'FCM token removed successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to remove FCM token',
          statusCode: 500
        }
      });
    }
  }

  @Delete('/tokens/all')
  async removeAllTokens(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;

      const firebaseService = new FirebaseService();
      await firebaseService.removeAllFcmTokens(userId);

      const response: ApiResponse = {
        success: true,
        message: 'All FCM tokens removed successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to remove all FCM tokens',
          statusCode: 500
        }
      });
    }
  }
}




