import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';

export interface PlanLimits {
  maxProjects: number; // -1 = unlimited
  maxScansPerProject: number; // -1 = unlimited
  maxScans: number; // -1 = unlimited
}

@Service()
export class PlanRestrictionService {
  /**
   * Get user's active subscription and plan limits
   */
  async getUserPlanLimits(userId: string): Promise<PlanLimits> {
    try {
      // Find active subscription - check status first, then endDate
      const subscription = await prisma.userSubscription.findFirst({
        where: {
          userId,
          status: 'ACTIVE',
          OR: [
            { endDate: null }, // Lifetime plans
            { endDate: { gt: new Date() } } // Active plans with future endDate
          ]
        },
        include: {
          plan: true
        },
        orderBy: {
          createdAt: 'desc' // Get the most recent subscription
        }
      });

      // If no active subscription, fetch FREE plan from database
      if (!subscription || !subscription.plan) {
        logger.info(`No active subscription found for user ${userId}, fetching FREE plan from database`);
        
        // Fetch FREE plan from database
        const freePlan = await prisma.servicePlan.findUnique({
          where: { name: 'FREE' }
        });

        if (!freePlan) {
          logger.warn('FREE plan not found in database, using default limits');
          return {
            maxProjects: 1,
            maxScansPerProject: 1,
            maxScans: 1
          };
        }

        const freeFeatures = freePlan.features as any;
        logger.info(`User ${userId} using FREE plan limits from database:`, {
          maxProjects: freeFeatures.maxProjects,
          maxScansPerProject: freeFeatures.maxScansPerProject,
          maxScans: freeFeatures.maxScans
        });

        return {
          maxProjects: freeFeatures.maxProjects ?? 1,
          maxScansPerProject: freeFeatures.maxScansPerProject ?? 1,
          maxScans: freeFeatures.maxScans ?? 1
        };
      }

      const features = subscription.plan.features as any;
      logger.info(`User ${userId} has active ${subscription.plan.name} plan with limits from database:`, {
        maxProjects: features.maxProjects,
        maxScansPerProject: features.maxScansPerProject,
        maxScans: features.maxScans
      });

      // Return limits from database, no hardcoded fallbacks
      return {
        maxProjects: features.maxProjects ?? 1,
        maxScansPerProject: features.maxScansPerProject ?? 1,
        maxScans: features.maxScans ?? 1
      };
    } catch (error) {
      logger.error('Error fetching user plan limits:', error);
      
      // Try to fetch FREE plan as last resort fallback
      try {
        const freePlan = await prisma.servicePlan.findUnique({
          where: { name: 'FREE' }
        });

        if (freePlan) {
          const freeFeatures = freePlan.features as any;
          logger.info('Using FREE plan from database as error fallback');
          return {
            maxProjects: freeFeatures.maxProjects ?? 1,
            maxScansPerProject: freeFeatures.maxScansPerProject ?? 1,
            maxScans: freeFeatures.maxScans ?? 1
          };
        }
      } catch (fallbackError) {
        logger.error('Error fetching FREE plan as fallback:', fallbackError);
      }

      // Only use hardcoded values if database is completely unavailable
      logger.warn('Database unavailable, using hardcoded fallback limits');
      return {
        maxProjects: 1,
        maxScansPerProject: 1,
        maxScans: 1
      };
    }
  }

  /**
   * Check if user can create a new project
   */
  async canCreateProject(userId: string): Promise<{ allowed: boolean; reason?: string }> {
    try {
      const limits = await this.getUserPlanLimits(userId);

      // Unlimited projects
      if (limits.maxProjects === -1) {
        return { allowed: true };
      }

      // Count active projects
      const projectCount = await prisma.project.count({
        where: {
          userId,
          status: 'ACTIVE'
        }
      });

      if (projectCount >= limits.maxProjects) {
        return {
          allowed: false,
          reason: `You have reached the maximum limit of ${limits.maxProjects} project(s) for your plan. Please upgrade to create more projects.`
        };
      }

      return { allowed: true };
    } catch (error) {
      logger.error('Error checking project creation limit:', error);
      return {
        allowed: false,
        reason: 'Unable to verify project limit. Please try again.'
      };
    }
  }

  /**
   * Check if user can run a scan on a project
   */
  async canRunScan(userId: string, projectId: string): Promise<{ allowed: boolean; reason?: string }> {
    try {
      const limits = await this.getUserPlanLimits(userId);

      // Unlimited scans per project
      if (limits.maxScansPerProject === -1) {
        return { allowed: true };
      }

      // Verify project belongs to user
      const project = await prisma.project.findFirst({
        where: {
          id: projectId,
          userId,
          status: 'ACTIVE'
        }
      });

      if (!project) {
        return {
          allowed: false,
          reason: 'Project not found or you do not have access to it.'
        };
      }

      // Count scans for this project
      const scanCount = await prisma.securityReport.count({
        where: {
          projectId,
          userId
        }
      });

      if (scanCount >= limits.maxScansPerProject) {
        return {
          allowed: false,
          reason: `You have reached the maximum limit of ${limits.maxScansPerProject} scan(s) per project for your plan. Please upgrade to run more scans.`
        };
      }

      return { allowed: true };
    } catch (error) {
      logger.error('Error checking scan limit:', error);
      return {
        allowed: false,
        reason: 'Unable to verify scan limit. Please try again.'
      };
    }
  }

  /**
   * Get user's current project count
   */
  async getUserProjectCount(userId: string): Promise<number> {
    try {
      return await prisma.project.count({
        where: {
          userId,
          status: 'ACTIVE'
        }
      });
    } catch (error) {
      logger.error('Error counting user projects:', error);
      return 0;
    }
  }

  /**
   * Get project's current scan count
   */
  async getProjectScanCount(projectId: string, userId: string): Promise<number> {
    try {
      return await prisma.securityReport.count({
        where: {
          projectId,
          userId
        }
      });
    } catch (error) {
      logger.error('Error counting project scans:', error);
      return 0;
    }
  }

  /**
   * Get user's plan information with usage stats and validity
   */
  async getUserPlanInfo(userId: string): Promise<{
    planName: string;
    limits: PlanLimits;
    usage: {
      projects: number;
      totalScans: number;
    };
    validity?: {
      startDate: string | null;
      endDate: string | null;
      billingCycle: string | null;
      isLifetime: boolean;
      daysRemaining: number | null;
    };
  }> {
    try {
      // Find active subscription - same logic as getUserPlanLimits
      const subscription = await prisma.userSubscription.findFirst({
        where: {
          userId,
          status: 'ACTIVE',
          OR: [
            { endDate: null }, // Lifetime plans
            { endDate: { gt: new Date() } } // Active plans with future endDate
          ]
        },
        include: {
          plan: true
        },
        orderBy: {
          createdAt: 'desc' // Get the most recent subscription
        }
      });

      const limits = await this.getUserPlanLimits(userId);
      const projectCount = await this.getUserProjectCount(userId);
      const totalScans = await prisma.securityReport.count({
        where: { userId }
      });

      // Get plan name from subscription or default to FREE
      const planName = subscription?.plan?.name || 'FREE';
      
      // Calculate validity information
      let validity = undefined;
      if (subscription) {
        const isLifetime = subscription.endDate === null;
        let daysRemaining: number | null = null;
        
        if (!isLifetime && subscription.endDate) {
          const now = new Date();
          const endDate = new Date(subscription.endDate);
          const diff = endDate.getTime() - now.getTime();
          daysRemaining = Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
        }

        validity = {
          startDate: subscription.startDate.toISOString(),
          endDate: subscription.endDate ? subscription.endDate.toISOString() : null,
          billingCycle: subscription.plan.billingCycle,
          isLifetime,
          daysRemaining
        };
      }
      
      logger.info(`Plan info for user ${userId}:`, {
        planName,
        limits,
        usage: {
          projects: projectCount,
          totalScans
        },
        validity
      });

      return {
        planName,
        limits,
        usage: {
          projects: projectCount,
          totalScans
        },
        validity
      };
    } catch (error) {
      logger.error('Error fetching user plan info:', error);
      throw new CustomError('Failed to fetch plan information', 500);
    }
  }
}
