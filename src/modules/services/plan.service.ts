import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import { Prisma } from '@prisma/client';

@Service()
export class PlanService {
  /**
   * Get all plans with optional filters
   */
  async getAllPlans(filters?: {
    search?: string;
    status?: string;
    isPopular?: boolean;
  }) {
    try {
      const where: Prisma.ServicePlanWhereInput = {};

      // Search filter
      if (filters?.search) {
        const searchTerm = filters.search.toLowerCase();
        where.OR = [
          { name: { contains: searchTerm, mode: 'insensitive' } },
          { description: { contains: searchTerm, mode: 'insensitive' } },
        ];
      }

      // Status filter
      if (filters?.status) {
        where.isActive = filters.status === 'active';
      }

      // Popular filter
      if (filters?.isPopular !== undefined) {
        const isPopularValue = typeof filters.isPopular === 'boolean' 
          ? filters.isPopular 
          : filters.isPopular === true;
        (where as any).isPopular = isPopularValue;
      }

      const plans = await prisma.servicePlan.findMany({
        where,
        orderBy: {
          createdAt: 'desc',
        },
      });

      // Transform database format to API format
      return plans.map(this.transformPlan);
    } catch (error) {
      logger.error('Error fetching plans:', error);
      throw new CustomError('Failed to retrieve plans', 500);
    }
  }

  /**
   * Get plan by ID
   */
  async getPlanById(id: string) {
    try {
      const plan = await prisma.servicePlan.findUnique({
        where: { id },
      });

      if (!plan) {
        throw new CustomError('Plan not found', 404);
      }

      return this.transformPlan(plan);
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching plan:', error);
      throw new CustomError('Failed to retrieve plan', 500);
    }
  }

  /**
   * Create a new plan
   */
  async createPlan(data: {
    name: string;
    price: number;
    description: string;
    features: string[] | Record<string, any>;
    deliveryDays: number;
    isPopular?: boolean;
    isActive?: boolean;
    currency?: string;
    billingCycle?: string;
    maxUsers?: number;
    maxStorage?: bigint | number;
  }) {
    try {
      // Check if plan with same name exists
      const existingPlan = await prisma.servicePlan.findUnique({
        where: { name: data.name },
      });

      if (existingPlan) {
        throw new CustomError('Plan with this name already exists', 400);
      }

      // Convert features array to JSON object if needed
      const featuresJson = Array.isArray(data.features)
        ? { featuresList: data.features }
        : data.features;

      // Create plan data object
      const planData: any = {
        name: data.name,
        description: data.description,
        price: new Prisma.Decimal(data.price),
        currency: data.currency || 'USD',
        billingCycle: (data.billingCycle as any) || 'MONTHLY',
        features: featuresJson,
        isActive: data.isActive ?? true,
        maxUsers: data.maxUsers,
        maxStorage: data.maxStorage ? BigInt(data.maxStorage) : null,
      };

      // Add optional fields if they exist in schema
      if (data.deliveryDays !== undefined) {
        planData.deliveryDays = data.deliveryDays;
      }
      if (data.isPopular !== undefined) {
        planData.isPopular = data.isPopular;
      }

      const plan = await prisma.servicePlan.create({
        data: planData,
      });

      return this.transformPlan(plan);
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error creating plan:', error);
      throw new CustomError('Failed to create plan', 500);
    }
  }

  /**
   * Update a plan
   */
  async updatePlan(id: string, data: Partial<{
    name: string;
    price: number;
    description: string;
    features: string[] | Record<string, any>;
    deliveryDays: number;
    isPopular: boolean;
    isActive: boolean;
    currency: string;
    billingCycle: string;
    maxUsers: number;
    maxStorage: bigint | number;
  }>) {
    try {
      // Check if plan exists
      const existingPlan = await prisma.servicePlan.findUnique({
        where: { id },
      });

      if (!existingPlan) {
        throw new CustomError('Plan not found', 404);
      }

      // If name is being updated, check for duplicates
      if (data.name && data.name !== existingPlan.name) {
        const duplicatePlan = await prisma.servicePlan.findUnique({
          where: { name: data.name },
        });

        if (duplicatePlan) {
          throw new CustomError('Plan with this name already exists', 400);
        }
      }

      // Prepare update data
      const updateData: any = {};

      if (data.name !== undefined) updateData.name = data.name;
      if (data.description !== undefined) updateData.description = data.description;
      if (data.price !== undefined) updateData.price = new Prisma.Decimal(data.price);
      if (data.currency !== undefined) updateData.currency = data.currency;
      if (data.billingCycle !== undefined) updateData.billingCycle = data.billingCycle;
      if (data.deliveryDays !== undefined) updateData.deliveryDays = data.deliveryDays;
      if (data.isPopular !== undefined) updateData.isPopular = data.isPopular;
      if (data.isActive !== undefined) updateData.isActive = data.isActive;
      if (data.maxUsers !== undefined) updateData.maxUsers = data.maxUsers;
      if (data.maxStorage !== undefined) updateData.maxStorage = data.maxStorage ? BigInt(data.maxStorage) : null;

      // Handle features conversion
      if (data.features !== undefined) {
        updateData.features = Array.isArray(data.features)
          ? { featuresList: data.features }
          : data.features;
      }

      const plan = await prisma.servicePlan.update({
        where: { id },
        data: updateData,
      });

      return this.transformPlan(plan);
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error updating plan:', error);
      throw new CustomError('Failed to update plan', 500);
    }
  }

  /**
   * Delete a plan
   * @param id - Plan ID to delete
   * @param force - If true, delete even if plan has active subscriptions (default: false)
   */
  async deletePlan(id: string, force: boolean = false) {
    try {
      // Check if plan exists
      const existingPlan = await prisma.servicePlan.findUnique({
        where: { id },
      });

      if (!existingPlan) {
        throw new CustomError('Plan not found', 404);
      }

      // Check if plan has active subscriptions (unless force delete)
      if (!force) {
        const subscriptions = await prisma.userSubscription.count({
          where: {
            planId: id,
            status: 'ACTIVE',
          },
        });

        if (subscriptions > 0) {
          throw new CustomError(
            `Cannot delete plan with ${subscriptions} active subscription(s). Please deactivate the plan first or use force delete.`,
            400
          );
        }
      }

      await prisma.servicePlan.delete({
        where: { id },
      });

      return { message: 'Plan deleted successfully' };
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error deleting plan:', error);
      throw new CustomError('Failed to delete plan', 500);
    }
  }

  /**
   * Transform database plan to API format
   */
  private transformPlan(plan: any) {
    // Extract features array from JSON
    let featuresArray: string[] = [];
    if (plan.features) {
      if (Array.isArray(plan.features)) {
        featuresArray = plan.features;
      } else if (plan.features.featuresList && Array.isArray(plan.features.featuresList)) {
        featuresArray = plan.features.featuresList;
      } else if (typeof plan.features === 'object') {
        // Convert object keys to feature strings
        featuresArray = Object.keys(plan.features).filter(key => plan.features[key] === true);
      }
    }

    return {
      id: plan.id,
      name: plan.name,
      price: parseFloat(plan.price.toString()),
      description: plan.description || '',
      features: featuresArray,
      deliveryDays: plan.deliveryDays || 0,
      isPopular: plan.isPopular || false,
      isActive: plan.isActive,
      createdAt: plan.createdAt.toISOString().split('T')[0],
      updatedAt: plan.updatedAt.toISOString().split('T')[0],
    };
  }
}

