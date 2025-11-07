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
      
      // Mock data based on push-notifications/page.tsx structure
      const notifications = [
        {
          id: '1',
          title: 'New Security Update Available',
          message: 'We\'ve released a new security scanner update with enhanced vulnerability detection. Update now to stay protected!',
          type: 'info',
          targetAudience: 'all',
          sentAt: '2024-01-15 10:30:00',
          status: 'sent',
          deliveryStats: {
            sent: 2847,
            delivered: 2756,
            opened: 1923,
            clicked: 456
          },
          createdAt: '2024-01-15 10:00:00',
          createdBy: 'Admin'
        },
        {
          id: '2',
          title: '50% OFF - Premium Security Suite',
          message: 'Limited time offer! Get 50% discount on our Premium Security Suite. Secure your business today!',
          type: 'promotion',
          targetAudience: 'trial',
          scheduledAt: '2024-01-20 14:00:00',
          status: 'scheduled',
          deliveryStats: {
            sent: 0,
            delivered: 0,
            opened: 0,
            clicked: 0
          },
          createdAt: '2024-01-18 09:00:00',
          createdBy: 'Admin'
        },
        {
          id: '3',
          title: 'Security Alert - Critical Vulnerability',
          message: 'We\'ve detected a critical security vulnerability in your system. Please run a security scan immediately.',
          type: 'error',
          targetAudience: 'active',
          sentAt: '2024-01-12 15:45:00',
          status: 'sent',
          deliveryStats: {
            sent: 1923,
            delivered: 1890,
            opened: 1789,
            clicked: 1234
          },
          createdAt: '2024-01-12 15:30:00',
          createdBy: 'Security Team'
        }
      ];

      // Apply filters
      let filteredNotifications = notifications;
      
      if (search) {
        const searchTerm = (search as string).toLowerCase();
        filteredNotifications = filteredNotifications.filter(notification => 
          notification.title.toLowerCase().includes(searchTerm) ||
          notification.message.toLowerCase().includes(searchTerm)
        );
      }
      
      if (status) {
        filteredNotifications = filteredNotifications.filter(notification => notification.status === status);
      }
      
      if (type) {
        filteredNotifications = filteredNotifications.filter(notification => notification.type === type);
      }
      
      if (targetAudience) {
        filteredNotifications = filteredNotifications.filter(notification => notification.targetAudience === targetAudience);
      }

      const response: ApiResponse = {
        success: true,
        data: filteredNotifications,
        message: 'Notifications retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve notifications',
          statusCode: 500
        }
      });
    }
  }

  @Get('/stats')
  async getNotificationStats(req: Request, res: Response): Promise<void> {
    try {
      const stats = {
        totalNotifications: 3,
        sentNotifications: 2,
        scheduledNotifications: 1,
        totalUsers: 2847,
        totalSent: 4770,
        totalDelivered: 4646,
        totalOpened: 3712,
        totalClicked: 1690
      };

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Notification stats retrieved successfully'
      };

      res.json(response);
    } catch (error) {
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

      const newNotification = {
        id: Date.now().toString(),
        title,
        message,
        type,
        targetAudience,
        scheduledAt: scheduledAt || null,
        status: scheduledAt ? 'scheduled' : 'draft',
        deliveryStats: {
          sent: 0,
          delivered: 0,
          opened: 0,
          clicked: 0
        },
        createdAt: new Date().toISOString(),
        createdBy: 'Admin'
      };

      const response: ApiResponse = {
        success: true,
        data: newNotification,
        message: 'Notification created successfully'
      };

      res.status(201).json(response);
    } catch (error) {
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

      // Get notification from database (for now using mock data structure)
      // In production, you'd fetch from database
      const notifications = [
        {
          id: '1',
          title: 'New Security Update Available',
          message: 'We\'ve released a new security scanner update with enhanced vulnerability detection. Update now to stay protected!',
          type: 'info',
          targetAudience: 'all',
        },
        {
          id: '2',
          title: '50% OFF - Premium Security Suite',
          message: 'Limited time offer! Get 50% discount on our Premium Security Suite. Secure your business today!',
          type: 'promotion',
          targetAudience: 'trial',
        },
        {
          id: '3',
          title: 'Security Alert - Critical Vulnerability',
          message: 'We\'ve detected a critical security vulnerability in your system. Please run a security scan immediately.',
          type: 'error',
          targetAudience: 'active',
        }
      ];

      const notification = notifications.find(n => n.id === id);
      if (!notification) {
        res.status(404).json({
          success: false,
          error: { message: 'Notification not found', statusCode: 404 }
        });
        return;
      }

      // Get target users based on audience
      let targetUserIds: string[] = [];

      if (notification.targetAudience === 'all') {
        const users = await prisma.user.findMany({
          where: { status: 'ACTIVE' },
          select: { id: true }
        });
        targetUserIds = users.map(u => u.id);
      } else {
        // For other audiences, you'd implement filtering logic
        // For now, sending to all active users
        const users = await prisma.user.findMany({
          where: { status: 'ACTIVE' },
          select: { id: true }
        });
        targetUserIds = users.map(u => u.id);
      }

      // Send push notifications
      const pushResult = await firebaseService.sendBulkNotification(targetUserIds, {
        title: notification.title,
        body: notification.message,
      });

      // Update notification in database with sent status
      // For now, just log the results
      logger.info('Push notification sent', {
        notificationId: id,
        targetUsers: targetUserIds.length,
        successCount: pushResult.successCount,
        failureCount: pushResult.failureCount,
      });

      const response: ApiResponse = {
        success: true,
        message: `Notification sent to ${pushResult.successCount} devices successfully`,
        data: {
          sent: pushResult.successCount,
          failed: pushResult.failureCount,
          total: targetUserIds.length,
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

      // Mock deletion - in real app, this would delete from database
      const response: ApiResponse = {
        success: true,
        message: 'Notification deleted successfully'
      };

      res.json(response);
    } catch (error) {
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
