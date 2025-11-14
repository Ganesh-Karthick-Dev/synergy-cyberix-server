import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { FirebaseService } from '../services/firebase.service';
import { prisma } from '../../config/db';
import { logger } from '../../utils/logger';

@Service()
@Controller('/api/notifications')
export class NotificationsController {
  @Get('/')
  async getAllNotifications(req: Request, res: Response): Promise<void> {
    try {
      const { search, status, type, targetAudience } = req.query;
      
      // Build where clause for filtering
      const where: any = {};
      
      if (search) {
        where.OR = [
          { title: { contains: search as string, mode: 'insensitive' } },
          { message: { contains: search as string, mode: 'insensitive' } }
        ];
      }
      
      if (status) {
        // Map frontend status to database status
        const statusMap: Record<string, string> = {
          'draft': 'DRAFT',
          'scheduled': 'SCHEDULED',
          'sent': 'SENT',
          'failed': 'CANCELLED' // Map failed to CANCELLED
        };
        where.status = statusMap[status as string] || undefined;
      }
      
      if (type) {
        // Map frontend type to database type
        const typeMap: Record<string, string> = {
          'info': 'GENERAL',
          'warning': 'SECURITY_ALERT',
          'success': 'FEATURE_ANNOUNCEMENT',
          'error': 'SECURITY_ALERT',
          'promotion': 'PROMOTIONAL'
        };
        where.type = typeMap[type as string] || 'GENERAL';
      }
      
      if (targetAudience) {
        // Map frontend audience to database target
        const audienceMap: Record<string, string> = {
          'all': 'ALL_USERS',
          'premium': 'PREMIUM_USERS',
          'trial': 'ACTIVE_USERS', // Using ACTIVE_USERS as fallback for trial
          'active': 'ACTIVE_USERS'
        };
        where.targetUsers = audienceMap[targetAudience as string] || 'ALL_USERS';
      }

      // Fetch notifications from database
      const notifications = await prisma.pushNotification.findMany({
        where,
        include: {
          createdBy: {
            select: {
              firstName: true,
              lastName: true,
              email: true
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      });

      // Transform to match frontend interface
      const transformedNotifications = notifications.map(notification => ({
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: this.mapTypeToFrontend(notification.type),
        targetAudience: this.mapTargetToFrontend(notification.targetUsers),
        sentAt: notification.sentAt ? notification.sentAt.toISOString() : undefined,
        scheduledAt: notification.scheduledAt ? notification.scheduledAt.toISOString() : undefined,
        status: this.mapStatusToFrontend(notification.status),
        deliveryStats: {
          sent: notification.sentCount || 0,
          delivered: notification.sentCount || 0, // Assuming sent = delivered for now
          opened: notification.readCount || 0,
          clicked: 0 // Not tracked in current schema
        },
        createdAt: notification.createdAt.toISOString(),
        createdBy: notification.createdBy 
          ? `${notification.createdBy.firstName} ${notification.createdBy.lastName}`.trim() || notification.createdBy.email
          : 'Admin'
      }));

      const response: ApiResponse = {
        success: true,
        data: transformedNotifications,
        message: 'Notifications retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      logger.error('Failed to retrieve notifications', { error });
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve notifications',
          statusCode: 500
        }
      });
    }
  }

  // Helper methods to map between database and frontend formats
  private mapTypeToFrontend(dbType: string): string {
    const typeMap: Record<string, string> = {
      'GENERAL': 'info',
      'SECURITY_ALERT': 'warning',
      'FEATURE_ANNOUNCEMENT': 'success',
      'PROMOTIONAL': 'promotion',
      'SYSTEM_UPDATE': 'info',
      'BILLING_REMINDER': 'info',
      'MAINTENANCE_NOTICE': 'warning'
    };
    // Default to 'info' for unknown types, but try to map SECURITY_ALERT to error if it's an error type
    return typeMap[dbType] || 'info';
  }

  private mapTargetToFrontend(dbTarget: string): string {
    const targetMap: Record<string, string> = {
      'ALL_USERS': 'all',
      'PREMIUM_USERS': 'premium',
      'ACTIVE_USERS': 'active',
      'SPECIFIC_USERS': 'all' // Map specific to all for frontend
    };
    return targetMap[dbTarget] || 'all';
  }

  private mapStatusToFrontend(dbStatus: string): string {
    const statusMap: Record<string, string> = {
      'DRAFT': 'draft',
      'SCHEDULED': 'scheduled',
      'SENT': 'sent',
      'CANCELLED': 'failed'
    };
    return statusMap[dbStatus] || 'draft';
  }

  @Get('/stats')
  async getNotificationStats(req: Request, res: Response): Promise<void> {
    try {
      // Get stats from database
      const [
        totalNotifications,
        sentNotifications,
        scheduledNotifications,
        totalUsers,
        notifications
      ] = await Promise.all([
        prisma.pushNotification.count(),
        prisma.pushNotification.count({ where: { status: 'SENT' } }),
        prisma.pushNotification.count({ where: { status: 'SCHEDULED' } }),
        prisma.user.count({ where: { status: 'ACTIVE' } }),
        prisma.pushNotification.findMany({
          select: {
            sentCount: true,
            readCount: true
          }
        })
      ]);

      // Calculate totals
      const totalSent = notifications.reduce((sum, n) => sum + n.sentCount, 0);
      const totalOpened = notifications.reduce((sum, n) => sum + n.readCount, 0);
      
      // Calculate averages
      const averageOpenRate = totalSent > 0 ? (totalOpened / totalSent) * 100 : 0;
      const averageClickRate = totalOpened > 0 ? 0 : 0; // Click tracking not implemented yet

      const stats = {
        totalNotifications,
        sentToday: sentNotifications, // You might want to filter by date
        scheduled: scheduledNotifications,
        totalRecipients: totalUsers,
        averageOpenRate: Math.round(averageOpenRate * 10) / 10,
        averageClickRate: Math.round(averageClickRate * 10) / 10
      };

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Notification stats retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      logger.error('Failed to retrieve notification stats', { error });
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve notification stats',
          statusCode: 500
        }
      });
    }
  }

  @Post('/')
  @Validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('message').notEmpty().withMessage('Message is required'),
    body('type').isIn(['info', 'warning', 'success', 'error', 'promotion']).withMessage('Invalid notification type'),
    body('targetAudience').isIn(['all', 'active', 'trial', 'premium']).withMessage('Invalid target audience')
  ])
  async createNotification(req: Request, res: Response): Promise<void> {
    try {
      const { title, message, type, targetAudience, scheduledAt } = req.body;

      // Get user ID from request (assuming it's set by auth middleware)
      const userId = (req as any).user?.id;

      // Map frontend values to database enums
      const typeMap: Record<string, string> = {
        'info': 'GENERAL',
        'warning': 'SECURITY_ALERT',
        'success': 'FEATURE_ANNOUNCEMENT',
        'error': 'SECURITY_ALERT',
        'promotion': 'PROMOTIONAL'
      };

      const targetMap: Record<string, string> = {
        'all': 'ALL_USERS',
        'premium': 'PREMIUM_USERS',
        'trial': 'ACTIVE_USERS', // Using ACTIVE_USERS as fallback for trial
        'active': 'ACTIVE_USERS'
      };

      // Create notification in database
      const notification = await prisma.pushNotification.create({
        data: {
          title,
          message,
          type: (typeMap[type] || 'GENERAL') as any,
          targetUsers: (targetMap[targetAudience] || 'ALL_USERS') as any,
          scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
          status: scheduledAt ? 'SCHEDULED' : 'DRAFT',
          createdById: userId || null,
          sentCount: 0,
          readCount: 0
        },
        include: {
          createdBy: {
            select: {
              firstName: true,
              lastName: true,
              email: true
            }
          }
        }
      });

      // Transform to match frontend interface
      const transformedNotification = {
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: this.mapTypeToFrontend(notification.type),
        targetAudience: this.mapTargetToFrontend(notification.targetUsers),
        scheduledAt: notification.scheduledAt ? notification.scheduledAt.toISOString() : undefined,
        status: this.mapStatusToFrontend(notification.status),
        deliveryStats: {
          sent: 0,
          delivered: 0,
          opened: 0,
          clicked: 0
        },
        createdAt: notification.createdAt.toISOString(),
        createdBy: notification.createdBy 
          ? `${notification.createdBy.firstName} ${notification.createdBy.lastName}`.trim() || notification.createdBy.email
          : 'Admin'
      };

      logger.info('Notification created', { notificationId: notification.id });

      const response: ApiResponse = {
        success: true,
        data: transformedNotification,
        message: 'Notification created successfully'
      };

      res.status(201).json(response);
    } catch (error) {
      logger.error('Failed to create notification', { error });
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to create notification',
          statusCode: 500
        }
      });
    }
  }

  @Post('/:id/send')
  async sendNotification(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const firebaseService = new FirebaseService();

      // Fetch notification from database
      const notification = await prisma.pushNotification.findUnique({
        where: { id }
      });

      if (!notification) {
        res.status(404).json({
          success: false,
          error: { message: 'Notification not found', statusCode: 404 }
        });
        return;
      }

      // Check if notification is already sent
      if (notification.status === 'SENT') {
        res.status(400).json({
          success: false,
          error: { message: 'Notification has already been sent', statusCode: 400 }
        });
        return;
      }

      // Get target user IDs based on target audience
      let targetUserIds: string[] = [];

      // Map database targetUsers enum to frontend targetAudience for filtering
      const dbTarget = notification.targetUsers;
      
      if (dbTarget === 'ALL_USERS') {
        // Get all active users
        const users = await prisma.user.findMany({
          where: { 
            status: 'ACTIVE',
            role: 'USER' // Exclude admin users
          },
          select: { id: true }
        });
        targetUserIds = users.map(u => u.id);
      } else if (dbTarget === 'PREMIUM_USERS') {
        // Get users with active subscriptions
        const premiumUsers = await prisma.user.findMany({
          where: {
            status: 'ACTIVE',
            role: 'USER',
            subscriptions: {
              some: {
                status: 'ACTIVE',
                OR: [
                  { endDate: null }, // Lifetime plans
                  { endDate: { gt: new Date() } } // Active plans with future endDate
                ]
              }
            }
          },
          select: { id: true }
        });
        targetUserIds = premiumUsers.map(u => u.id);
      } else if (dbTarget === 'ACTIVE_USERS') {
        // Get all active users (same as ALL_USERS for now)
        const users = await prisma.user.findMany({
          where: { 
            status: 'ACTIVE',
            role: 'USER'
          },
          select: { id: true }
        });
        targetUserIds = users.map(u => u.id);
      } else if (dbTarget === 'SPECIFIC_USERS' && notification.userIds && notification.userIds.length > 0) {
        // Use specific user IDs from notification
        targetUserIds = notification.userIds;
      } else {
        // Default to all active users
        const users = await prisma.user.findMany({
          where: { 
            status: 'ACTIVE',
            role: 'USER'
          },
          select: { id: true }
        });
        targetUserIds = users.map(u => u.id);
      }

      if (targetUserIds.length === 0) {
        res.status(400).json({
          success: false,
          error: { message: 'No target users found for this notification', statusCode: 400 }
        });
        return;
      }

      // Get all FCM tokens for target users (bulk fetch from user_fcm_token table)
      // This is handled by sendBulkNotification which calls getBulkFcmTokens internally
      // sendBulkNotification will get all active FCM tokens for the provided user IDs
      const pushResult = await firebaseService.sendBulkNotification(targetUserIds, {
        title: notification.title,
        body: notification.message,
        data: notification.data as Record<string, string> | undefined,
        image: notification.imageUrl ?? undefined,
      });

      // Update notification in database with sent status
      await prisma.pushNotification.update({
        where: { id },
        data: {
          status: 'SENT',
          sentAt: new Date(),
          sentCount: pushResult.successCount,
        }
      });

      logger.info('Push notification sent', {
        notificationId: id,
        targetUsers: targetUserIds.length,
        targetTokens: pushResult.successCount + pushResult.failureCount,
        successCount: pushResult.successCount,
        failureCount: pushResult.failureCount,
      });

      const response: ApiResponse = {
        success: true,
        message: `Notification sent to ${pushResult.successCount} devices successfully`,
        data: {
          sent: pushResult.successCount,
          failed: pushResult.failureCount,
          totalDevices: pushResult.successCount + pushResult.failureCount,
          totalUsers: targetUserIds.length,
        }
      };

      res.json(response);
    } catch (error) {
      logger.error('Failed to send notification', { error, notificationId: req.params.id });
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to send notification',
          statusCode: 500
        }
      });
    }
  }

  @Delete('/:id')
  async deleteNotification(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // Delete notification from database
      await prisma.pushNotification.delete({
        where: { id }
      });

      logger.info('Notification deleted', { notificationId: id });

      const response: ApiResponse = {
        success: true,
        message: 'Notification deleted successfully'
      };

      res.json(response);
    } catch (error) {
      logger.error('Failed to delete notification', { error, notificationId: req.params.id });
      
      // Handle case where notification doesn't exist
      if ((error as any).code === 'P2025') {
        res.status(404).json({
          success: false,
          error: {
            message: 'Notification not found',
            statusCode: 404
          }
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to delete notification',
          statusCode: 500
        }
      });
    }
  }
}
