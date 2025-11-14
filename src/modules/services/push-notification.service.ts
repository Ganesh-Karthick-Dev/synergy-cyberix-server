import { prisma } from '../../config/db';
import { PushNotificationType, PushNotificationTarget, PushNotificationStatus } from '@prisma/client';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';

export interface PushNotificationData {
  id: string;
  title: string;
  message: string;
  type: PushNotificationType;
  targetUsers: PushNotificationTarget;
  userIds: string[];
  data: any;
  imageUrl: string | null;
  scheduledAt: Date | null;
  sentAt: Date | null;
  status: PushNotificationStatus;
  sentCount: number;
  readCount: number;
  createdAt: Date;
  updatedAt: Date;
  createdById: string | null;
}

export interface CreatePushNotificationDto {
  title: string;
  message: string;
  type?: PushNotificationType;
  targetUsers?: PushNotificationTarget;
  userIds?: string[];
  data?: any;
  imageUrl?: string;
  scheduledAt?: Date;
}

export interface UpdatePushNotificationDto {
  title?: string;
  message?: string;
  type?: PushNotificationType;
  targetUsers?: PushNotificationTarget;
  userIds?: string[];
  data?: any;
  imageUrl?: string;
  scheduledAt?: Date;
  status?: PushNotificationStatus;
}

@Service()
export class PushNotificationService {
  async getAllNotifications(filters?: {
    status?: PushNotificationStatus;
    type?: PushNotificationType;
    search?: string;
    page?: number;
    limit?: number;
  }): Promise<{
    notifications: PushNotificationData[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }> {
    const { status, type, search, page = 1, limit = 10 } = filters || {};
    const skip = (page - 1) * limit;

    const where: any = {};

    if (status) {
      where.status = status;
    }

    if (type) {
      where.type = type;
    }

    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' as const } },
        { message: { contains: search, mode: 'insensitive' as const } }
      ];
    }

    const [notifications, total] = await Promise.all([
      prisma.pushNotification.findMany({
        where,
        include: {
          createdBy: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit
      }),
      prisma.pushNotification.count({ where })
    ]);

    return {
      notifications,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  }

  async getNotificationById(id: string): Promise<PushNotificationData | null> {
    const notification = await prisma.pushNotification.findUnique({
      where: { id },
      include: {
        createdBy: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    return notification;
  }

  async createNotification(
    notificationData: CreatePushNotificationDto,
    createdById?: string
  ): Promise<PushNotificationData> {
    const notification = await prisma.pushNotification.create({
      data: {
        ...notificationData,
        createdById
      },
      include: {
        createdBy: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    logger.info('Push notification created', {
      notificationId: notification.id,
      title: notification.title,
      createdById
    });

    return notification;
  }

  async updateNotification(
    id: string,
    updateData: UpdatePushNotificationDto
  ): Promise<PushNotificationData> {
    const notification = await prisma.pushNotification.findUnique({
      where: { id }
    });

    if (!notification) {
      throw new CustomError('Push notification not found', 404);
    }

    const updatedNotification = await prisma.pushNotification.update({
      where: { id },
      data: updateData,
      include: {
        createdBy: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    logger.info('Push notification updated', {
      notificationId: id,
      title: notification.title
    });

    return updatedNotification;
  }

  async deleteNotification(id: string): Promise<void> {
    const notification = await prisma.pushNotification.findUnique({
      where: { id }
    });

    if (!notification) {
      throw new CustomError('Push notification not found', 404);
    }

    await prisma.pushNotification.delete({
      where: { id }
    });

    logger.info('Push notification deleted', {
      notificationId: id,
      title: notification.title
    });
  }

  async sendNotification(id: string): Promise<PushNotificationData> {
    const notification = await prisma.pushNotification.findUnique({
      where: { id }
    });

    if (!notification) {
      throw new CustomError('Push notification not found', 404);
    }

    if (notification.status === PushNotificationStatus.SENT) {
      throw new CustomError('Notification has already been sent', 400);
    }

    // Update notification status and sent timestamp
    const updatedNotification = await prisma.pushNotification.update({
      where: { id },
      data: {
        status: PushNotificationStatus.SENT,
        sentAt: new Date()
      },
      include: {
        createdBy: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    // TODO: Implement actual FCM sending logic here
    // This would integrate with Firebase Cloud Messaging to send push notifications

    logger.info('Push notification sent', {
      notificationId: id,
      title: notification.title
    });

    return updatedNotification;
  }

  async getNotificationStats(): Promise<{
    total: number;
    sent: number;
    scheduled: number;
    draft: number;
  }> {
    const [total, sent, scheduled, draft] = await Promise.all([
      prisma.pushNotification.count(),
      prisma.pushNotification.count({ where: { status: PushNotificationStatus.SENT } }),
      prisma.pushNotification.count({ where: { status: PushNotificationStatus.SCHEDULED } }),
      prisma.pushNotification.count({ where: { status: PushNotificationStatus.DRAFT } })
    ]);

    return {
      total,
      sent,
      scheduled,
      draft
    };
  }

  async duplicateNotification(id: string): Promise<PushNotificationData> {
    const notification = await prisma.pushNotification.findUnique({
      where: { id }
    });

    if (!notification) {
      throw new CustomError('Push notification not found', 404);
    }

    const duplicatedNotification = await prisma.pushNotification.create({
      data: {
        title: `${notification.title} (Copy)`,
        message: notification.message,
        type: notification.type,
        targetUsers: notification.targetUsers,
        userIds: notification.userIds,
        data: notification.data || {},
        imageUrl: notification.imageUrl,
        status: PushNotificationStatus.DRAFT
      },
      include: {
        createdBy: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    logger.info('Push notification duplicated', {
      originalId: id,
      newId: duplicatedNotification.id
    });

    return duplicatedNotification;
  }
}
