const { PrismaClient, PushNotificationType, PushNotificationTarget, PushNotificationStatus } = require('@prisma/client');

const prisma = new PrismaClient();

async function createTestPushNotification() {
  try {
    console.log('Creating test push notification...');

    const notification = await prisma.pushNotification.upsert({
      where: { id: 'test-notification' },
      update: {},
      create: {
        id: 'test-notification',
        title: 'Test Push Notification',
        message: 'This is a test push notification for the admin panel.',
        type: PushNotificationType.GENERAL,
        targetUsers: PushNotificationTarget.ALL_USERS,
        userIds: [],
        status: PushNotificationStatus.DRAFT,
        data: { test: true },
        createdById: null // Will be set by admin later
      }
    });

    console.log('✅ Test push notification created:', notification);

    // Test retrieving all notifications
    const notifications = await prisma.pushNotification.findMany({
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

    console.log('📋 All push notifications:', notifications.length);
    console.log('📊 Notification details:', notifications.map(n => ({
      id: n.id,
      title: n.title,
      status: n.status,
      type: n.type
    })));

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createTestPushNotification();
