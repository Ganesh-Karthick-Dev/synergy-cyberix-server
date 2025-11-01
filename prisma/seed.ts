import { PrismaClient, UserRole, UserStatus, BillingCycle, SecurityCategory, SeverityLevel, ReportStatus, CampaignStatus, AdStatus, NotificationType } from '@prisma/client';
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
    prisma.servicePlan.create({
      data: {
        name: 'FREE',
        description: 'Free tier with basic security features',
        price: 0.00,
        currency: 'USD',
        billingCycle: BillingCycle.MONTHLY,
        features: {
          basicSecurityScans: true,
          limitedThreatIntelligence: true,
          communitySupport: true,
          maxScans: 5
        },
        maxUsers: 1,
        maxStorage: 100 * 1024 * 1024 // 100MB
      }
    }),
    prisma.servicePlan.create({
      data: {
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
          maxScans: 100
        },
        maxUsers: 25,
        maxStorage: 10 * 1024 * 1024 * 1024 // 10GB
      }
    }),
    prisma.servicePlan.create({
      data: {
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
    prisma.userSubscription.create({
      data: {
        userId: users[0].id,
        planId: servicePlans[0].id,
        status: 'ACTIVE',
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        autoRenew: true,
        paymentMethod: 'credit_card'
      }
    }),
    prisma.userSubscription.create({
      data: {
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

  // Create security tools
  const securityTools = await Promise.all([
    prisma.securityTool.create({
      data: {
        name: 'Vulnerability Scanner',
        description: 'Automated vulnerability scanning tool',
        category: SecurityCategory.VULNERABILITY_SCANNER,
        config: {
          scanDepth: 'deep',
          reportFormat: 'pdf',
          schedule: 'weekly'
        }
      }
    }),
    prisma.securityTool.create({
      data: {
        name: 'Penetration Testing Suite',
        description: 'Comprehensive penetration testing tools',
        category: SecurityCategory.PENETRATION_TESTING,
        config: {
          testTypes: ['web', 'network', 'mobile'],
          reportFormat: 'html',
          schedule: 'monthly'
        }
      }
    }),
    prisma.securityTool.create({
      data: {
        name: 'Compliance Checker',
        description: 'Automated compliance checking for various standards',
        category: SecurityCategory.COMPLIANCE_CHECKER,
        config: {
          standards: ['PCI-DSS', 'HIPAA', 'SOX', 'GDPR'],
          reportFormat: 'excel',
          schedule: 'quarterly'
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
    prisma.notificationTemplate.create({
      data: {
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
    prisma.notificationTemplate.create({
      data: {
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

  console.log('🎉 Cyberix Security Admin database seeding completed successfully!');
  console.log('📊 Summary:');
  console.log(`   - Users: ${await prisma.user.count()}`);
  console.log(`   - Service Plans: ${await prisma.servicePlan.count()}`);
  console.log(`   - Security Tools: ${await prisma.securityTool.count()}`);
  console.log(`   - Security Reports: ${await prisma.securityReport.count()}`);
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
