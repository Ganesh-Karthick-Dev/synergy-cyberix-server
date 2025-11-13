import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import { Prisma } from '@prisma/client';
import { RazorpayService } from './razorpay.service';

@Service()
export class PlanService {
  private razorpayService: RazorpayService;

  constructor() {
    this.razorpayService = new RazorpayService();
  }

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
    deliveryDays?: number;
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
   * Create payment order for a plan
   */
  async createPlanPaymentOrder(planId: string, userId: string) {
    try {
      console.log('[Plan Service] ===== CREATING PLAN PAYMENT ORDER =====')
      console.log('[Plan Service] Plan ID:', planId)
      console.log('[Plan Service] User ID:', userId)

      // Get plan details
      console.log('[Plan Service] Fetching plan details...')
      const plan = await this.getPlanById(planId);
      console.log('[Plan Service] Plan details:', {
        id: plan.id,
        name: plan.name,
        price: plan.price,
        currency: (plan as any).currency || 'USD',
        isActive: plan.isActive
      })

      if (!plan.isActive) {
        console.log('[Plan Service] ❌ Plan is not active')
        throw new CustomError('Plan is not active', 400);
      }

      // Convert price to paise (Razorpay expects amount in smallest currency unit)
      const amountInPaise = Math.round(plan.price * 100);
      console.log('[Plan Service] Amount conversion:', {
        planPrice: plan.price,
        amountInPaise: amountInPaise,
        calculation: `${plan.price} * 100 = ${amountInPaise}`
      })

      // Generate a shorter receipt (Razorpay limit: 40 chars max)
      const timestamp = Date.now().toString().slice(-8) // Last 8 digits of timestamp
      const shortPlanId = planId.slice(-8) // Last 8 chars of plan ID
      const receipt = `p_${shortPlanId}_${timestamp}` // Max ~20 chars

      const orderData = {
        amount: amountInPaise,
        currency: 'INR',
        userId,
        planId,
        receipt,
        notes: {
          description: `Subscription to ${plan.name} plan`,
          planId,
          userId,
          planName: plan.name
        }
      };

      console.log('[Plan Service] Order data prepared:', orderData)
      console.log('[Plan Service] Calling Razorpay service...')

      const paymentOrder = await this.razorpayService.createOrder(orderData);

      logger.info(`Payment order created for plan ${planId} by user ${userId}`);

      console.log('[Plan Service] Preparing response...')
      const transformedPlan = this.transformPlanForPayment(plan);
      console.log('[Plan Service] Plan transformed successfully')

      const response = {
        ...paymentOrder,
        plan: transformedPlan
      };
      console.log('[Plan Service] Response prepared:', {
        paymentOrderId: paymentOrder.id,
        razorpayOrderId: paymentOrder.razorpayOrderId,
        planId: transformedPlan.id,
        planName: transformedPlan.name
      });

      return response;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error creating plan payment order:', error);
      throw new CustomError('Failed to create payment order for plan', 500);
    }
  }

  /**
   * Get user's active subscription
   */
  async getUserActiveSubscription(userId: string) {
    try {
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

      if (!subscription) {
        return null;
      }

      // Transform subscription to ensure BigInt values are serialized correctly
      return {
        id: subscription.id,
        planId: subscription.planId,
        status: subscription.status,
        startDate: subscription.startDate,
        endDate: subscription.endDate,
        autoRenew: subscription.autoRenew,
        paymentMethod: subscription.paymentMethod,
        createdAt: subscription.createdAt,
        updatedAt: subscription.updatedAt,
        plan: {
          id: subscription.plan.id,
          name: subscription.plan.name,
          description: subscription.plan.description,
          price: parseFloat(subscription.plan.price.toString()),
          currency: subscription.plan.currency,
          billingCycle: subscription.plan.billingCycle,
          features: subscription.plan.features,
          deliveryDays: subscription.plan.deliveryDays,
          isPopular: subscription.plan.isPopular,
          isActive: subscription.plan.isActive,
          maxUsers: subscription.plan.maxUsers,
          maxStorage: subscription.plan.maxStorage ? subscription.plan.maxStorage.toString() : null, // Convert BigInt to string
          createdAt: subscription.plan.createdAt,
          updatedAt: subscription.plan.updatedAt
        }
      };
    } catch (error) {
      logger.error('Error fetching user active subscription:', error);
      throw new CustomError('Failed to retrieve active subscription', 500);
    }
  }

  /**
   * Transform database plan to API format
   */
  private transformPlan(plan: any) {
    console.log('[Plan Service] Transforming plan object:', {
      id: plan.id,
      name: plan.name,
      price: plan.price,
      hasFeatures: !!plan.features,
      hasCreatedAt: !!plan.createdAt,
      hasUpdatedAt: !!plan.updatedAt
    });

    // Extract features array from JSON while preserving maxProjects
    let featuresArray: string[] = [];
    let maxProjects: number | null = null;
    let maxScansPerProject: number | null = null;
    let maxScans: number | null = null;
    
    if (plan.features) {
      if (Array.isArray(plan.features)) {
        featuresArray = plan.features;
      } else if (typeof plan.features === 'object') {
        // Extract featuresList if it exists
        if (plan.features.featuresList && Array.isArray(plan.features.featuresList)) {
          featuresArray = plan.features.featuresList;
        } else {
          // Convert object keys to feature strings (for boolean features)
          featuresArray = Object.keys(plan.features).filter(
            key => plan.features[key] === true && 
            key !== 'maxProjects' && 
            key !== 'maxScansPerProject' && 
            key !== 'maxScans'
          );
        }
        
        // Extract numeric limits
        maxProjects = plan.features.maxProjects !== undefined ? plan.features.maxProjects : null;
        maxScansPerProject = plan.features.maxScansPerProject !== undefined ? plan.features.maxScansPerProject : null;
        maxScans = plan.features.maxScans !== undefined ? plan.features.maxScans : null;
      }
    }

    // Safely handle date fields
    const formatDate = (date: any) => {
      if (!date) return null;
      try {
        const d = new Date(date);
        return d.toISOString().split('T')[0];
      } catch (error) {
        console.warn('[Plan Service] Invalid date format:', date);
        return null;
      }
    };

    // Build features object with both array and limits
    const featuresObject: any = featuresArray.length > 0 ? featuresArray : [];
    if (maxProjects !== null || maxScansPerProject !== null || maxScans !== null) {
      // If we have limits, return as object
      const result = {
        id: plan.id,
        name: plan.name,
        price: parseFloat(plan.price.toString()),
        description: plan.description || '',
        features: featuresArray, // Keep array for backward compatibility
        maxProjects: maxProjects, // Add maxProjects at root level
        maxScansPerProject: maxScansPerProject,
        maxScans: maxScans,
        deliveryDays: plan.deliveryDays || 0,
        isPopular: plan.isPopular || false,
        isActive: plan.isActive || true,
        createdAt: formatDate(plan.createdAt),
        updatedAt: formatDate(plan.updatedAt),
      };
      console.log('[Plan Service] Plan transformation result with limits:', result);
      return result;
    }

    const result = {
      id: plan.id,
      name: plan.name,
      price: parseFloat(plan.price.toString()),
      description: plan.description || '',
      features: featuresArray,
      deliveryDays: plan.deliveryDays || 0,
      isPopular: plan.isPopular || false,
      isActive: plan.isActive || true,
      createdAt: formatDate(plan.createdAt),
      updatedAt: formatDate(plan.updatedAt),
    };

    console.log('[Plan Service] Plan transformation result:', result);
    return result;
  }

  /**
   * Transform database plan to payment order format (minimal fields)
   */
  private transformPlanForPayment(plan: any) {
    console.log('[Plan Service] Transforming plan for payment:', {
      id: plan.id,
      name: plan.name,
      price: plan.price
    });

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

    // Return only the fields needed by the frontend PaymentOrder interface
    const result = {
      id: plan.id,
      name: plan.name,
      price: parseFloat(plan.price.toString()),
      description: plan.description || '',
      features: featuresArray,
      isPopular: plan.isPopular || false,
    };

    console.log('[Plan Service] Payment plan transformation result:', result);
    return result;
  }
}

