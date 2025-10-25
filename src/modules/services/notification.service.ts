import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { Service } from '../../decorators/service.decorator';
import { logger } from '../../utils/logger';

export interface LoginNotification {
  userId: string;
  newDeviceInfo: string;
  newIpAddress: string;
  newUserAgent: string;
  timestamp: Date;
}

@Service()
export class NotificationService {
  /**
   * Send login notification to user about new device login
   */
  async sendLoginNotification(notification: LoginNotification): Promise<void> {
    try {
      // Create notification record in database
      await prisma.notification.create({
        data: {
          userId: notification.userId,
          type: 'SECURITY_ALERT',
          title: 'New Device Login Detected',
          message: `Your account was accessed from a new device: ${notification.newDeviceInfo}`,
          data: {
            deviceInfo: notification.newDeviceInfo,
            ipAddress: notification.newIpAddress,
            userAgent: notification.newUserAgent,
            timestamp: notification.timestamp.toISOString()
          },
          isRead: false
        }
      });

      // Log the security event
      logger.warn('New device login detected', {
        userId: notification.userId,
        deviceInfo: notification.newDeviceInfo,
        ipAddress: notification.newIpAddress,
        userAgent: notification.newUserAgent
      });

    } catch (error) {
      logger.error('Failed to send login notification', { error, notification });
      throw new CustomError('Failed to send login notification', 500);
    }
  }

  /**
   * Get unread notifications for a user
   */
  async getUserNotifications(userId: string, limit: number = 10): Promise<any[]> {
    try {
      return await prisma.notification.findMany({
        where: {
          userId,
          isRead: false
        },
        orderBy: {
          createdAt: 'desc'
        },
        take: limit
      });
    } catch (error) {
      logger.error('Failed to get user notifications', { error, userId });
      throw new CustomError('Failed to get user notifications', 500);
    }
  }

  /**
   * Mark notification as read
   */
  async markNotificationAsRead(notificationId: string, userId: string): Promise<void> {
    try {
      await prisma.notification.updateMany({
        where: {
          id: notificationId,
          userId
        },
        data: {
          isRead: true
        }
      });
    } catch (error) {
      logger.error('Failed to mark notification as read', { error, notificationId, userId });
      throw new CustomError('Failed to mark notification as read', 500);
    }
  }

  /**
   * Mark all notifications as read for a user
   */
  async markAllNotificationsAsRead(userId: string): Promise<void> {
    try {
      await prisma.notification.updateMany({
        where: {
          userId,
          isRead: false
        },
        data: {
          isRead: true
        }
      });
    } catch (error) {
      logger.error('Failed to mark all notifications as read', { error, userId });
      throw new CustomError('Failed to mark all notifications as read', 500);
    }
  }

  /**
   * Get notification statistics for a user
   */
  async getNotificationStats(userId: string): Promise<{
    total: number;
    unread: number;
    highPriority: number;
  }> {
    try {
      const [total, unread, highPriority] = await Promise.all([
        prisma.notification.count({
          where: { userId }
        }),
        prisma.notification.count({
          where: { userId, isRead: false }
        }),
        prisma.notification.count({
          where: { userId, isRead: false, type: 'SECURITY_ALERT' }
        })
      ]);

      return { total, unread, highPriority };
    } catch (error) {
      logger.error('Failed to get notification stats', { error, userId });
      throw new CustomError('Failed to get notification stats', 500);
    }
  }
}
