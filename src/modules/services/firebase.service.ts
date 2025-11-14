import * as admin from 'firebase-admin';
import { Service } from '../../decorators/service.decorator';
import { prisma } from '../../config/db';
import { logger } from '../../utils/logger';
import { CustomError } from '../../middlewares/error.middleware';

interface PushNotificationPayload {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  image?: string;
  data?: Record<string, string>;
  clickAction?: string;
}

interface SendNotificationOptions {
  userId?: string;
  tokens?: string[];
  title: string;
  body: string;
  data?: Record<string, any>;
  image?: string;
  icon?: string;
}

@Service()
export class FirebaseService {
  private initialized = false;

  constructor() {
    this.initializeFirebase();
  }

  private initializeFirebase(): void {
    try {
      if (!process.env.FIREBASE_PROJECT_ID ||
          !process.env.FIREBASE_PRIVATE_KEY ||
          !process.env.FIREBASE_CLIENT_EMAIL) {
        logger.warn('Firebase credentials not found, push notifications will not work');
        return;
      }

      if (admin.apps.length === 0) {
        admin.initializeApp({
          credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          }),
        });
      }

      this.initialized = true;
      logger.info('Firebase Admin SDK initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Firebase Admin SDK', { error });
      this.initialized = false;
    }
  }

  /**
   * Store FCM token for a user
   */
  async storeFcmToken(userId: string, fcmToken: string, deviceInfo?: {
    userAgent?: string;
    ipAddress?: string;
    deviceInfo?: string;
  }): Promise<void> {
    try {
      // Check if token already exists for this user
      const existingToken = await prisma.userFcmToken.findFirst({
        where: {
          userId,
          fcmToken,
        },
      });

      if (existingToken) {
        // Update last used time
        await prisma.userFcmToken.update({
          where: { id: existingToken.id },
          data: {
            lastUsedAt: new Date(),
            isActive: true,
            ...deviceInfo,
          },
        });
        logger.info('Updated existing FCM token', { userId, tokenId: existingToken.id });
      } else {
        // Create new token
        await prisma.userFcmToken.create({
          data: {
            userId,
            fcmToken,
            isActive: true,
            lastUsedAt: new Date(),
            ...deviceInfo,
          },
        });
        logger.info('Stored new FCM token', { userId });
      }
    } catch (error) {
      logger.error('Failed to store FCM token', { error, userId });
      throw new CustomError('Failed to store FCM token', 500);
    }
  }

  /**
   * Remove FCM token for a user
   */
  async removeFcmToken(userId: string, fcmToken: string): Promise<void> {
    try {
      await prisma.userFcmToken.updateMany({
        where: {
          userId,
          fcmToken,
        },
        data: {
          isActive: false,
        },
      });
      logger.info('Deactivated FCM token', { userId });
    } catch (error) {
      logger.error('Failed to remove FCM token', { error, userId });
      throw new CustomError('Failed to remove FCM token', 500);
    }
  }

  /**
   * Remove all FCM tokens for a user (logout from all devices)
   */
  async removeAllFcmTokens(userId: string): Promise<void> {
    try {
      await prisma.userFcmToken.updateMany({
        where: { userId },
        data: { isActive: false },
      });
      logger.info('Deactivated all FCM tokens for user', { userId });
    } catch (error) {
      logger.error('Failed to remove all FCM tokens', { error, userId });
      throw new CustomError('Failed to remove all FCM tokens', 500);
    }
  }

  /**
   * Get active FCM tokens for a user
   */
  async getUserFcmTokens(userId: string): Promise<string[]> {
    try {
      const tokens = await prisma.userFcmToken.findMany({
        where: {
          userId,
          isActive: true,
        },
        select: {
          fcmToken: true,
        },
      });

      return tokens.map(t => t.fcmToken);
    } catch (error) {
      logger.error('Failed to get user FCM tokens', { error, userId });
      throw new CustomError('Failed to get user FCM tokens', 500);
    }
  }

  /**
   * Get active FCM tokens for multiple users (bulk notifications)
   */
  async getBulkFcmTokens(userIds: string[]): Promise<string[]> {
    try {
      const tokens = await prisma.userFcmToken.findMany({
        where: {
          userId: { in: userIds },
          isActive: true,
        },
        select: {
          fcmToken: true,
        },
      });

      return tokens.map(t => t.fcmToken);
    } catch (error) {
      logger.error('Failed to get bulk FCM tokens', { error, userIds });
      throw new CustomError('Failed to get bulk FCM tokens', 500);
    }
  }

  /**
   * Send push notification to specific tokens
   */
  async sendNotificationToTokens(tokens: string[], payload: PushNotificationPayload): Promise<{ successCount: number; failureCount: number; responses: any[] }> {
    if (!this.initialized) {
      throw new CustomError('Firebase not initialized', 500);
    }

    try {
      const message: admin.messaging.MulticastMessage = {
        tokens,
        notification: {
          title: payload.title,
          body: payload.body,
          imageUrl: payload.image,
        },
        data: payload.data,
        webpush: {
          notification: {
            title: payload.title,
            body: payload.body,
            icon: payload.icon || '/icon-192x192.png',
            badge: payload.badge || '/icon-192x192.png',
            image: payload.image,
            requireInteraction: true,
            actions: payload.clickAction ? [{
              action: 'open',
              title: 'Open',
            }] : undefined,
          },
          fcmOptions: {
            link: payload.clickAction,
          },
        },
        android: {
          notification: {
            title: payload.title,
            body: payload.body,
            imageUrl: payload.image,
            icon: payload.icon,
            clickAction: payload.clickAction,
          },
        },
        apns: {
          payload: {
            aps: {
              alert: {
                title: payload.title,
                body: payload.body,
              },
              sound: 'default',
              badge: 1,
            },
          },
        },
      };

      // Use sendEachForMulticast for efficient bulk sending (handles up to 500 tokens per call)
      // Official Firebase method for sending the same message to multiple tokens
      // Reference: https://firebase.google.com/docs/cloud-messaging/send/admin-sdk
      const BATCH_SIZE = 500;
      const batches: string[][] = [];
      
      for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
        batches.push(tokens.slice(i, i + BATCH_SIZE));
      }

      let totalSuccessCount = 0;
      let totalFailureCount = 0;
      const allResponses: any[] = [];

      // Process each batch
      for (const batch of batches) {
        // Create multicast message for this batch
        const batchMessage: admin.messaging.MulticastMessage = {
          ...message,
          tokens: batch,
        };

        // Use sendEachForMulticast (official Firebase method for bulk sending)
        const batchResponse = await admin.messaging().sendEachForMulticast(batchMessage);
        
        totalSuccessCount += batchResponse.successCount;
        totalFailureCount += batchResponse.failureCount;
        
        // Map responses to our format
        batchResponse.responses.forEach((response: admin.messaging.SendResponse, index: number) => {
          allResponses.push({
            success: response.success,
            error: response.error ? {
              code: response.error.code,
              message: response.error.message,
            } : undefined,
            token: batch[index],
          });
        });
      }

      const response = {
        responses: allResponses,
        successCount: totalSuccessCount,
        failureCount: totalFailureCount,
      };
      logger.info('Push notification sent', {
        successCount: response.successCount,
        failureCount: response.failureCount,
        tokensCount: tokens.length,
      });

      return response;
    } catch (error) {
      logger.error('Failed to send push notification', { error, tokensCount: tokens.length });
      throw new CustomError('Failed to send push notification', 500);
    }
  }

  /**
   * Send notification to a specific user
   */
  async sendNotificationToUser(options: SendNotificationOptions): Promise<{ successCount: number; failureCount: number; responses: any[] }> {
    const tokens = options.tokens || await this.getUserFcmTokens(options.userId!);

    if (tokens.length === 0) {
      logger.warn('No FCM tokens found for user', { userId: options.userId });
      return {
        responses: [],
        successCount: 0,
        failureCount: 0,
      };
    }

    const payload: PushNotificationPayload = {
      title: options.title,
      body: options.body,
      data: options.data,
      image: options.image,
      icon: options.icon,
    };

    return this.sendNotificationToTokens(tokens, payload);
  }

  /**
   * Send bulk notification to multiple users
   */
  async sendBulkNotification(userIds: string[], payload: PushNotificationPayload): Promise<{ successCount: number; failureCount: number; responses: any[] }> {
    const tokens = await this.getBulkFcmTokens(userIds);

    if (tokens.length === 0) {
      logger.warn('No FCM tokens found for bulk notification', { userIds });
      return {
        responses: [],
        successCount: 0,
        failureCount: 0,
      };
    }

    return this.sendNotificationToTokens(tokens, payload);
  }

  /**
   * Send notification to all active users
   */
  async sendNotificationToAllUsers(payload: PushNotificationPayload): Promise<{ successCount: number; failureCount: number; responses: any[] }> {
    try {
      // Get all active users
      const activeUsers = await prisma.user.findMany({
        where: { status: 'ACTIVE' },
        select: { id: true },
      });

      const userIds = activeUsers.map(user => user.id);
      return this.sendBulkNotification(userIds, payload);
    } catch (error) {
      logger.error('Failed to send notification to all users', { error });
      throw new CustomError('Failed to send notification to all users', 500);
    }
  }

  /**
   * Clean up inactive/expired FCM tokens
   */
  async cleanupExpiredTokens(): Promise<void> {
    try {
      // Remove tokens that haven't been used for 30 days
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      const result = await prisma.userFcmToken.deleteMany({
        where: {
          OR: [
            { isActive: false },
            {
              lastUsedAt: {
                lt: thirtyDaysAgo,
              },
            },
          ],
        },
      });

      logger.info('Cleaned up expired FCM tokens', { deletedCount: result.count });
    } catch (error) {
      logger.error('Failed to cleanup expired FCM tokens', { error });
      throw new CustomError('Failed to cleanup expired FCM tokens', 500);
    }
  }
}
