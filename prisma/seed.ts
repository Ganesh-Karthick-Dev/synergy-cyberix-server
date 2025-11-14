import { PrismaClient, UserRole, UserStatus, BillingCycle, SecurityCategory, SeverityLevel, ReportStatus, CampaignStatus, AdStatus, NotificationType, PushNotificationType, PushNotificationTarget, PushNotificationStatus } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting Cyberix Security Admin database seeding...');

  // Note: Only USER and ADMIN roles are allowed
  // SUPER_ADMIN role has been removed for security

  // Create admin users
  const adminPassword = await bcrypt.hash('12345', 12);
  
  // First admin user - webnox@admin.com
  const admin = await prisma.user.upsert({
    where: { email: 'webnox@admin.com' },
    update: {},
    create: {
      email: 'webnox@admin.com',
      username: 'webnox_admin',
      password: adminPassword,
      firstName: 'Webnox',
      lastName: 'Admin',
      role: UserRole.ADMIN,
      status: UserStatus.ACTIVE,
      emailVerified: true,
      twoFactorEnabled: false
    }
  });

  // Second admin user - webnox1@admin.com
  const admin2 = await prisma.user.upsert({
    where: { email: 'webnox1@admin.com' },
    update: {},
    create: {
      email: 'webnox1@admin.com',
      username: 'webnox1_admin',
      password: adminPassword,
      firstName: 'Webnox',
      lastName: 'Admin 2',
      role: UserRole.ADMIN,
      status: UserStatus.ACTIVE,
      emailVerified: true,
      twoFactorEnabled: false
    }
  });

  console.log('✅ Admin users created:', [
    { id: admin.id, email: admin.email, password: '12345' },
    { id: admin2.id, email: admin2.email, password: '12345' }
  ]);

  // Create test users
  const users = await Promise.all([
    prisma.user.upsert({
      where: { email: 'user1@cyberix.com' },
      update: {},
      create: {
        email: 'user1@cyberix.com',
        username: 'user1',
        password: await bcrypt.hash('user123', 12),
        firstName: 'John',
        lastName: 'Doe',
        role: UserRole.USER,
        status: UserStatus.ACTIVE,
        emailVerified: true
      }
    }),
    prisma.user.upsert({
      where: { email: 'user2@cyberix.com' },
      update: {},
      create: {
        email: 'user2@cyberix.com',
        username: 'user2',
        password: await bcrypt.hash('user123', 12),
        firstName: 'Jane',
        lastName: 'Smith',
        role: UserRole.USER, // Changed from CUSTOMER to USER
        status: UserStatus.ACTIVE,
        emailVerified: true
      }
    })
  ]);

  console.log('✅ Test users created:', users.map(user => ({ id: user.id, email: user.email })));

  // Create service plans
  const servicePlans = await Promise.all([
    prisma.servicePlan.upsert({
      where: { name: 'FREE' },
      update: {},
      create: {
        name: 'FREE',
        description: 'Free tier with basic security features',
        price: 0.00,
        currency: 'USD',
        billingCycle: BillingCycle.MONTHLY,
        features: {
          basicSecurityScans: true,
          limitedThreatIntelligence: true,
          communitySupport: true,
          maxProjects: 1,
          maxScansPerProject: 1,
          maxScans: 1
        },
        maxUsers: 1,
        maxStorage: 100 * 1024 * 1024 // 100MB
      }
    }),
    prisma.servicePlan.upsert({
      where: { name: 'PRO' },
      update: {},
      create: {
        name: 'PRO',
        description: 'Professional security features for growing businesses',
        price: 99.99,
        currency: 'USD',
        billingCycle: BillingCycle.MONTHLY,
        features: {
          vulnerabilityScanning: true,
          penetrationTesting: true,
          complianceChecking: true,
          advancedReporting: true,
          prioritySupport: true,
          maxProjects: 10, // 10 projects for PRO plan
          maxScansPerProject: -1, // -1 = unlimited
          maxScans: -1 // -1 = unlimited
        },
        maxUsers: 25,
        maxStorage: 10 * 1024 * 1024 * 1024 // 10GB
      }
    }),
    prisma.servicePlan.upsert({
      where: { name: 'PRO_PLUS' },
      update: {},
      create: {
        name: 'PRO_PLUS',
        description: 'Premium security solution for large organizations',
        price: 299.99,
        currency: 'USD',
        billingCycle: BillingCycle.MONTHLY,
        features: {
          vulnerabilityScanning: true,
          penetrationTesting: true,
          complianceChecking: true,
          threatDetection: true,
          accessControl: true,
          encryption: true,
          monitoring: true,
          customReporting: true,
          dedicatedSupport: true,
          maxProjects: -1, // -1 = unlimited
          maxScansPerProject: -1, // -1 = unlimited
          unlimitedScans: true
        },
        maxUsers: -1, // Unlimited
        maxStorage: -1 // Unlimited
      }
    })
  ]);

  console.log('✅ Service plans created:', servicePlans.map(plan => plan.name));

  // Create user subscriptions
  const subscriptions = await Promise.all([
    prisma.userSubscription.upsert({
      where: {
        userId_planId: {
          userId: users[0].id,
          planId: servicePlans[0].id
        }
      },
      update: {
        status: 'ACTIVE',
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        autoRenew: true,
        paymentMethod: 'credit_card'
      },
      create: {
        userId: users[0].id,
        planId: servicePlans[0].id,
        status: 'ACTIVE',
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        autoRenew: true,
        paymentMethod: 'credit_card'
      }
    }),
    prisma.userSubscription.upsert({
      where: {
        userId_planId: {
          userId: users[1].id,
          planId: servicePlans[1].id
        }
      },
      update: {
        status: 'ACTIVE',
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        autoRenew: true,
        paymentMethod: 'paypal'
      },
      create: {
        userId: users[1].id,
        planId: servicePlans[1].id,
        status: 'ACTIVE',
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        autoRenew: true,
        paymentMethod: 'paypal'
      }
    })
  ]);

  console.log('✅ User subscriptions created:', subscriptions.length);

  // Create security tools - 7 specific tools as requested
  const securityTools = await Promise.all([
    prisma.securityTool.upsert({
      where: { name: 'Overview Scan' },
      update: {},
      create: {
        name: 'Overview Scan',
        description: 'Comprehensive security overview and initial assessment scan',
        category: SecurityCategory.OVERVIEW_SCAN,
        isActive: true,
        config: {
          scanDepth: 'comprehensive',
          includeMetrics: true,
          generateReport: true,
          riskAssessment: true
        }
      }
    }),
    prisma.securityTool.upsert({
      where: { name: 'Port, Network, Server Scan' },
      update: {},
      create: {
        name: 'Port, Network, Server Scan',
        description: 'Combined port scanning, network discovery, and server analysis',
        category: SecurityCategory.VULNERABILITY_SCANNER,
        isActive: true,
        config: {
          portRange: '1-65535',
          networkDiscovery: true,
          serverAnalysis: true,
          serviceDetection: true,
          vulnerabilityMapping: true
        }
      }
    }),
    prisma.securityTool.upsert({
      where: { name: 'Shopify Cloud Shield' },
      update: {},
      create: {
        name: 'Shopify Cloud Shield',
        description: 'Advanced security protection for Shopify stores and cloud infrastructure',
        category: SecurityCategory.CLOUD_SECURITY,
        isActive: true,
        config: {
          platformType: 'shopify',
          ddosProtection: true,
          malwareScanning: true,
          sslEnforcement: true,
          backupProtection: true
        }
      }
    }),
    prisma.securityTool.upsert({
      where: { name: 'Website Security Audit' },
      update: {},
      create: {
        name: 'Website Security Audit',
        description: 'Complete website security assessment and vulnerability audit',
        category: SecurityCategory.COMPLIANCE_CHECKER,
        isActive: true,
        config: {
          auditTypes: ['OWASP Top 10', 'PCI DSS', 'GDPR'],
          automatedScanning: true,
          manualReview: false,
          complianceReporting: true,
          remediationSuggestions: true
        }
      }
    }),
    prisma.securityTool.upsert({
      where: { name: 'Phishing & Brand Abuse Detection' },
      update: {},
      create: {
        name: 'Phishing & Brand Abuse Detection',
        description: 'Advanced detection of phishing attempts and brand abuse activities',
        category: SecurityCategory.THREAT_DETECTION,
        isActive: true,
        config: {
          phishingDetection: true,
          brandMonitoring: true,
          urlAnalysis: true,
          emailScanning: true,
          realTimeAlerts: true
        }
      }
    }),
    prisma.securityTool.upsert({
      where: { name: 'Malware and Defacement Monitor' },
      update: {},
      create: {
        name: 'Malware and Defacement Monitor',
        description: 'Continuous monitoring for malware infections and website defacement',
        category: SecurityCategory.MONITORING,
        isActive: true,
        config: {
          malwareScanning: true,
          defacementDetection: true,
          realTimeMonitoring: true,
          automatedCleanup: false,
          alertFrequency: 'immediate'
        }
      }
    }),
    prisma.securityTool.upsert({
      where: { name: 'WordPress Cloud Shield' },
      update: {},
      create: {
        name: 'WordPress Cloud Shield',
        description: 'Comprehensive security protection for WordPress sites and cloud hosting',
        category: SecurityCategory.CLOUD_SECURITY,
        isActive: true,
        config: {
          platformType: 'wordpress',
          pluginSecurity: true,
          coreProtection: true,
          bruteForcePrevention: true,
          backupSecurity: true
        }
      }
    })
  ]);

  console.log('✅ Security tools created:', securityTools.map(tool => tool.name));

  // Create security reports
  const securityReports = await Promise.all([
    prisma.securityReport.create({
      data: {
        userId: users[0].id,
        toolId: securityTools[0].id,
        title: 'Critical Vulnerability Found',
        content: 'SQL injection vulnerability detected in login form',
        severity: SeverityLevel.CRITICAL,
        status: ReportStatus.OPEN,
        metadata: {
          cve: 'CVE-2023-1234',
          affectedComponent: 'login.php',
          recommendation: 'Implement parameterized queries'
        }
      }
    }),
    prisma.securityReport.create({
      data: {
        userId: users[1].id,
        toolId: securityTools[1].id,
        title: 'Penetration Test Results',
        content: 'Network penetration test completed successfully',
        severity: SeverityLevel.MEDIUM,
        status: ReportStatus.IN_PROGRESS,
        metadata: {
          testDuration: '2 hours',
          vulnerabilitiesFound: 3,
          recommendations: 5
        }
      }
    })
  ]);

  console.log('✅ Security reports created:', securityReports.length);

  // Create ad campaigns
  const adCampaigns = await Promise.all([
    prisma.adCampaign.create({
      data: {
        title: 'Cyberix Security Awareness',
        description: 'Promote security awareness among users',
        content: 'Learn about the latest security threats and how to protect yourself',
        targetAudience: {
          ageRange: [25, 65],
          interests: ['technology', 'security'],
          location: 'global'
        },
        budget: 1000.00,
        spent: 250.50,
        status: CampaignStatus.ACTIVE,
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      }
    })
  ]);

  console.log('✅ Ad campaigns created:', adCampaigns.length);

  // Create ads
  const ads = await Promise.all([
    prisma.ad.create({
      data: {
        campaignId: adCampaigns[0].id,
        title: 'Secure Your Business Today',
        content: 'Protect your business with our advanced security solutions',
        imageUrl: 'https://example.com/security-ad.jpg',
        linkUrl: 'https://cyberix.com/security-plans',
        status: AdStatus.ACTIVE,
        impressions: 1500,
        clicks: 45
      }
    })
  ]);

  console.log('✅ Ads created:', ads.length);

  // Create notifications
  const notifications = await Promise.all([
    prisma.notification.create({
      data: {
        userId: users[0].id,
        title: 'Security Alert',
        message: 'Critical vulnerability detected in your system',
        type: NotificationType.SECURITY_ALERT,
        data: {
          severity: 'critical',
          actionRequired: true
        },
        sentAt: new Date()
      }
    }),
    prisma.notification.create({
      data: {
        title: 'System Update Available',
        message: 'New security features have been added to your plan',
        type: NotificationType.SYSTEM_UPDATE,
        data: {
          version: '2.1.0',
          features: ['enhanced scanning', 'new reports']
        },
        sentAt: new Date()
      }
    })
  ]);

  console.log('✅ Notifications created:', notifications.length);

  // Create notification templates
  const notificationTemplates = await Promise.all([
    prisma.notificationTemplate.upsert({
      where: { name: 'Security Alert Template' },
      update: {
        title: 'Security Alert: {{severity}}',
        message: 'A {{severity}} security issue has been detected: {{description}}',
        type: NotificationType.SECURITY_ALERT,
        variables: {
          severity: 'string',
          description: 'string',
          timestamp: 'datetime'
        }
      },
      create: {
        name: 'Security Alert Template',
        title: 'Security Alert: {{severity}}',
        message: 'A {{severity}} security issue has been detected: {{description}}',
        type: NotificationType.SECURITY_ALERT,
        variables: {
          severity: 'string',
          description: 'string',
          timestamp: 'datetime'
        }
      }
    }),
    prisma.notificationTemplate.upsert({
      where: { name: 'Billing Reminder Template' },
      update: {
        title: 'Payment Due: {{amount}}',
        message: 'Your subscription payment of {{amount}} is due on {{dueDate}}',
        type: NotificationType.BILLING_REMINDER,
        variables: {
          amount: 'currency',
          dueDate: 'date'
        }
      },
      create: {
        name: 'Billing Reminder Template',
        title: 'Payment Due: {{amount}}',
        message: 'Your subscription payment of {{amount}} is due on {{dueDate}}',
        type: NotificationType.BILLING_REMINDER,
        variables: {
          amount: 'currency',
          dueDate: 'date'
        }
      }
    })
  ]);

  console.log('✅ Notification templates created:', notificationTemplates.length);

  // Create dashboard metrics
  const dashboardMetrics = await Promise.all([
    prisma.dashboardMetric.create({
      data: {
        name: 'Total Users',
        value: 1250,
        category: 'users',
        metadata: {
          growth: 15.5,
          period: 'monthly'
        }
      }
    }),
    prisma.dashboardMetric.create({
      data: {
        name: 'Active Subscriptions',
        value: 890,
        category: 'subscriptions',
        metadata: {
          growth: 8.2,
          period: 'monthly'
        }
      }
    }),
    prisma.dashboardMetric.create({
      data: {
        name: 'Security Scans Completed',
        value: 15420,
        category: 'security',
        metadata: {
          growth: 25.3,
          period: 'monthly'
        }
      }
    }),
    prisma.dashboardMetric.create({
      data: {
        name: 'Revenue',
        value: 125000.50,
        category: 'revenue',
        metadata: {
          growth: 12.8,
          period: 'monthly'
        }
      }
    })
  ]);

  console.log('✅ Dashboard metrics created:', dashboardMetrics.length);

  // Create audit logs
  const auditLogs = await Promise.all([
    prisma.auditLog.create({
      data: {
        userId: admin.id, // Use admin instead of superAdmin
        action: 'CREATE_USER',
        resource: 'User',
        details: {
          targetUserId: users[0].id,
          changes: { role: 'USER', status: 'ACTIVE' }
        },
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    }),
    prisma.auditLog.create({
      data: {
        userId: admin.id,
        action: 'UPDATE_SUBSCRIPTION',
        resource: 'UserSubscription',
        details: {
          subscriptionId: subscriptions[0].id,
          changes: { status: 'ACTIVE' }
        },
        ipAddress: '192.168.1.2',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    })
  ]);

  console.log('✅ Audit logs created:', auditLogs.length);

  // Create push notifications
  const pushNotifications = await Promise.all([
    prisma.pushNotification.upsert({
      where: { id: 'welcome-notification' },
      update: {},
      create: {
        id: 'welcome-notification',
        title: 'Welcome to Cyberix Security!',
        message: 'Thank you for joining our cybersecurity platform. Start scanning your website today!',
        type: PushNotificationType.GENERAL,
        targetUsers: PushNotificationTarget.ALL_USERS,
        userIds: [],
        status: PushNotificationStatus.DRAFT,
        createdById: admin.id
      }
    }),
    prisma.pushNotification.upsert({
      where: { id: 'security-alert-notification' },
      update: {},
      create: {
        id: 'security-alert-notification',
        title: 'Security Alert: New Vulnerability Detected',
        message: 'A new high-severity vulnerability has been discovered. Update your security tools immediately.',
        type: PushNotificationType.SECURITY_ALERT,
        targetUsers: PushNotificationTarget.ALL_USERS,
        userIds: [],
        status: PushNotificationStatus.SENT,
        sentAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
        sentCount: 150,
        createdById: admin.id
      }
    }),
    prisma.pushNotification.upsert({
      where: { id: 'maintenance-notification' },
      update: {},
      create: {
        id: 'maintenance-notification',
        title: 'Maintenance Notice',
        message: 'Scheduled maintenance will occur tonight from 2-4 AM. Some features may be temporarily unavailable.',
        type: PushNotificationType.MAINTENANCE_NOTICE,
        targetUsers: PushNotificationTarget.ALL_USERS,
        userIds: [],
        status: PushNotificationStatus.SCHEDULED,
        scheduledAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // Tomorrow
        createdById: admin.id
      }
    }),
    prisma.pushNotification.upsert({
      where: { id: 'promotional-notification' },
      update: {},
      create: {
        id: 'promotional-notification',
        title: 'Exclusive Premium Features',
        message: 'Upgrade to PRO plan and get access to advanced scanning tools and priority support!',
        type: PushNotificationType.PROMOTIONAL,
        targetUsers: PushNotificationTarget.ACTIVE_USERS,
        userIds: [],
        status: PushNotificationStatus.DRAFT,
        imageUrl: 'https://example.com/pro-upgrade.jpg',
        createdById: admin.id
      }
    }),
    prisma.pushNotification.upsert({
      where: { id: 'billing-reminder-notification' },
      update: {},
      create: {
        id: 'billing-reminder-notification',
        title: 'Payment Reminder',
        message: 'Your subscription will expire in 3 days. Renew now to continue enjoying our services.',
        type: PushNotificationType.BILLING_REMINDER,
        targetUsers: PushNotificationTarget.PREMIUM_USERS,
        userIds: [],
        status: PushNotificationStatus.DRAFT,
        createdById: admin.id
      }
    })
  ]);

  console.log('✅ Push notifications created:', pushNotifications.length);

  console.log('🎉 Cyberix Security Admin database seeding completed successfully!');
  console.log('📊 Summary:');
  console.log(`   - Users: ${await prisma.user.count()}`);
  console.log(`   - Service Plans: ${await prisma.servicePlan.count()}`);
  console.log(`   - Security Tools: ${await prisma.securityTool.count()}`);
  console.log(`   - Security Reports: ${await prisma.securityReport.count()}`);
  console.log(`   - Push Notifications: ${await prisma.pushNotification.count()}`);
  console.log(`   - Ad Campaigns: ${await prisma.adCampaign.count()}`);
  console.log(`   - Notifications: ${await prisma.notification.count()}`);
  console.log(`   - Dashboard Metrics: ${await prisma.dashboardMetric.count()}`);
}

main()
  .catch((e) => {
    console.error('❌ Error during seeding:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
