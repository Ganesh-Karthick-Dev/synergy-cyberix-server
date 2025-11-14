import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { PushNotificationService, CreatePushNotificationDto, UpdatePushNotificationDto } from '../services/push-notification.service';
import { PushNotificationType, PushNotificationTarget, PushNotificationStatus } from '@prisma/client';

@Service()
@Controller('/api/push-notifications')
export class PushNotificationController {
  private pushNotificationService: PushNotificationService;

  constructor() {
    this.pushNotificationService = new PushNotificationService();
  }

  @Get('/')
  async getAllNotifications(req: Request, res: Response): Promise<void> {
    try {
      const {
        status,
        type,
        search,
        page = '1',
        limit = '10'
      } = req.query;

      const filters: any = {};

      if (status) {
        filters.status = status as PushNotificationStatus;
      }

      if (type) {
        filters.type = type as PushNotificationType;
      }

      if (search) {
        filters.search = search as string;
      }

      filters.page = parseInt(page as string, 10) || 1;
      filters.limit = parseInt(limit as string, 10) || 10;

      const result = await this.pushNotificationService.getAllNotifications(filters);

      const response: ApiResponse = {
        success: true,
        data: {
          notifications: result.notifications,
          pagination: result.pagination
        },
        message: 'Push notifications retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve push notifications',
          statusCode: 500
        }
      });
    }
  }

  @Get('/stats')
  async getNotificationStats(req: Request, res: Response): Promise<void> {
    try {
      const stats = await this.pushNotificationService.getNotificationStats();

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Notification statistics retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve notification statistics',
          statusCode: 500
        }
      });
    }
  }

  @Get('/:id')
  async getNotificationById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Notification ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const notification = await this.pushNotificationService.getNotificationById(id);

      if (!notification) {
        res.status(404).json({
          success: false,
          error: {
            message: 'Push notification not found',
            statusCode: 404
          }
        });
        return;
      }

      const response: ApiResponse = {
        success: true,
        data: notification,
        message: 'Push notification retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve push notification',
          statusCode: 500
        }
      });
    }
  }

  @Post('/')
  async createNotification(req: Request, res: Response): Promise<void> {
    try {
      const notificationData: CreatePushNotificationDto = req.body;
      const createdById = (req as any).user?.id; // From auth middleware

      const notification = await this.pushNotificationService.createNotification(
        notificationData,
        createdById
      );

      const response: ApiResponse = {
        success: true,
        data: notification,
        message: 'Push notification created successfully'
      };

      res.status(201).json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to create push notification',
          statusCode: 500
        }
      });
    }
  }

  @Put('/:id')
  async updateNotification(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData: UpdatePushNotificationDto = req.body;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Notification ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const notification = await this.pushNotificationService.updateNotification(id, updateData);

      const response: ApiResponse = {
        success: true,
        data: notification,
        message: 'Push notification updated successfully'
      };

      res.json(response);
    } catch (error) {
      const statusCode = error instanceof Error && 'statusCode' in error ? (error as any).statusCode : 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to update push notification',
          statusCode
        }
      });
    }
  }

  @Post('/:id/send')
  async sendNotification(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Notification ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const notification = await this.pushNotificationService.sendNotification(id);

      const response: ApiResponse = {
        success: true,
        data: notification,
        message: 'Push notification sent successfully'
      };

      res.json(response);
    } catch (error) {
      const statusCode = error instanceof Error && 'statusCode' in error ? (error as any).statusCode : 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to send push notification',
          statusCode
        }
      });
    }
  }

  @Post('/:id/duplicate')
  async duplicateNotification(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Notification ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const duplicatedNotification = await this.pushNotificationService.duplicateNotification(id);

      const response: ApiResponse = {
        success: true,
        data: duplicatedNotification,
        message: 'Push notification duplicated successfully'
      };

      res.status(201).json(response);
    } catch (error) {
      const statusCode = error instanceof Error && 'statusCode' in error ? (error as any).statusCode : 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to duplicate push notification',
          statusCode
        }
      });
    }
  }

  @Delete('/:id')
  async deleteNotification(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Notification ID is required',
            statusCode: 400
          }
        });
        return;
      }

      await this.pushNotificationService.deleteNotification(id);

      const response: ApiResponse = {
        success: true,
        message: 'Push notification deleted successfully'
      };

      res.json(response);
    } catch (error) {
      const statusCode = error instanceof Error && 'statusCode' in error ? (error as any).statusCode : 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to delete push notification',
          statusCode
        }
      });
    }
  }

  @Get('/types/list')
  async getNotificationTypes(req: Request, res: Response): Promise<void> {
    try {
      const types = Object.values(PushNotificationType);

      const response: ApiResponse = {
        success: true,
        data: types,
        message: 'Notification types retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve notification types',
          statusCode: 500
        }
      });
    }
  }

  @Get('/targets/list')
  async getNotificationTargets(req: Request, res: Response): Promise<void> {
    try {
      const targets = Object.values(PushNotificationTarget);

      const response: ApiResponse = {
        success: true,
        data: targets,
        message: 'Notification targets retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve notification targets',
          statusCode: 500
        }
      });
    }
  }
}
