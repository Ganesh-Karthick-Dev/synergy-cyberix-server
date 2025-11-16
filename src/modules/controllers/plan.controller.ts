import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { Use } from '../../decorators/middleware.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { PlanService } from '../services/plan.service';
import { authenticate } from '../../middlewares/auth.middleware';
import { prisma } from '../../config/db';
import { logger } from '../../utils/logger';

@Service()
@Controller('/api/plans')
export class PlanController {
  private planService: PlanService;

  constructor() {
    this.planService = new PlanService();
  }

  @Get('/')
  async getAllPlans(req: Request, res: Response): Promise<void> {
    try {
      const { search, status, isPopular } = req.query;
      
      // Convert isPopular query param to boolean or undefined
      let isPopularBool: boolean | undefined = undefined;
      if (isPopular !== undefined) {
        if (typeof isPopular === 'string') {
          isPopularBool = isPopular === 'true';
        } else if (typeof isPopular === 'boolean') {
          isPopularBool = isPopular;
        }
      }
      
      const plans = await this.planService.getAllPlans({
        search: search as string | undefined,
        status: status as string | undefined,
        isPopular: isPopularBool,
      });

      const response: ApiResponse = {
        success: true,
        data: plans,
        message: 'Plans retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve plans',
          statusCode
        }
      });
    }
  }

  @Get('/:id')
  async getPlanById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      
      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Plan ID is required',
            statusCode: 400
          }
        });
        return;
      }
      
      const plan = await this.planService.getPlanById(id);

      const response: ApiResponse = {
        success: true,
        data: plan,
        message: 'Plan retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve plan',
          statusCode
        }
      });
    }
  }

  @Post('/')
  @Validate([
    body('name').notEmpty().withMessage('Plan name is required'),
    body('price').isNumeric().withMessage('Price must be a number'),
    body('description').notEmpty().withMessage('Description is required'),
    body('features').isArray({ min: 1 }).withMessage('At least one feature is required')
  ])
  async createPlan(req: Request, res: Response): Promise<void> {
    try {
      const { name, price, description, features, isPopular = false, isActive = true } = req.body;

      const plan = await this.planService.createPlan({
        name,
        price: Number(price),
        description,
        features,
        isPopular,
        isActive,
      });

      const response: ApiResponse = {
        success: true,
        data: plan,
        message: 'Plan created successfully'
      };

      res.status(201).json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to create plan',
          statusCode
        }
      });
    }
  }

  @Put('/:id')
  async updatePlan(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      
      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Plan ID is required',
            statusCode: 400
          }
        });
        return;
      }
      
      const updateData = req.body;

      const updatedPlan = await this.planService.updatePlan(id, updateData);

      const response: ApiResponse = {
        success: true,
        data: updatedPlan,
        message: 'Plan updated successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to update plan',
          statusCode
        }
      });
    }
  }

  @Put('/:id/toggle-status')
  async togglePlanStatus(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Plan ID is required',
            statusCode: 400
          }
        });
        return;
      }

      // Get current plan to toggle status
      const plan = await this.planService.getPlanById(id);
      const newStatus = !plan.isActive;

      const updatedPlan = await this.planService.updatePlan(id, { isActive: newStatus });

      const response: ApiResponse = {
        success: true,
        data: updatedPlan,
        message: `Plan ${newStatus ? 'activated' : 'deactivated'} successfully`
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to update plan status',
          statusCode
        }
      });
    }
  }

  /**
   * Create payment order for a plan
   */
  @Use(authenticate)
  @Post('/:id/payment-order')
  async createPlanPaymentOrder(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Plan ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const paymentOrder = await this.planService.createPlanPaymentOrder(id, userId);

      const response: ApiResponse = {
        success: true,
        data: paymentOrder,
        message: 'Payment order created successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to create payment order',
          statusCode
        }
      });
    }
  }

  /**
   * Get user's active subscription
   */
  @Get('/subscription/active')
  @Use(authenticate)
  async getUserActiveSubscription(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const subscription = await this.planService.getUserActiveSubscription(userId);

      const response: ApiResponse = {
        success: true,
        data: subscription,
        message: subscription ? 'Active subscription retrieved successfully' : 'No active subscription found'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve active subscription',
          statusCode
        }
      });
    }
  }

  /**
   * Admin: Get user's active subscription by user ID
   */
  @Get('/subscription/user/:userId')
  @Use(authenticate)
  async getAdminUserSubscription(req: Request, res: Response): Promise<void> {
    try {
      // Check if user is admin
      if (req.user?.role !== 'ADMIN') {
        res.status(403).json({
          success: false,
          error: {
            message: 'Admin access required',
            statusCode: 403
          }
        });
        return;
      }

      const { userId } = req.params;

      if (!userId) {
        res.status(400).json({
          success: false,
          error: {
            message: 'User ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const subscription = await this.planService.getUserActiveSubscription(userId);

      const response: ApiResponse = {
        success: true,
        data: subscription,
        message: subscription ? 'User subscription retrieved successfully' : 'No active subscription found for user'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve user subscription',
          statusCode
        }
      });
    }
  }

  /**
   * Get user's purchased plans (queue)
   * Also creates PurchasedPlan records for existing payment orders that don't have them (migration)
   */
  @Get('/purchased')
  @Use(authenticate)
  async getUserPurchasedPlans(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;

      logger.info(`[Purchased Plans] Fetching purchased plans for user ${userId}`);

      // Get ALL payment orders with planId for this user (regardless of status)
      const allPaymentOrders = await prisma.paymentOrder.findMany({
        where: {
          userId,
          planId: { not: null },
        },
        include: {
          plan: true,
          purchasedPlan: true,
          payments: {
            where: {
              status: 'COMPLETED',
            },
            take: 1, // Just need to know if there's a completed payment
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      logger.info(`[Purchased Plans] Found ${allPaymentOrders.length} payment orders with planId for user ${userId}`);
      allPaymentOrders.forEach((order, index) => {
        logger.info(`[Purchased Plans] Order ${index + 1}: id=${order.id}, planId=${order.planId}, orderStatus=${order.status}, hasCompletedPayment=${order.payments.length > 0}, hasPurchasedPlan=${!!order.purchasedPlan}`);
      });

      // Filter: orders that have completed payments AND don't have PurchasedPlan records
      const paymentOrdersWithoutPurchasedPlans = allPaymentOrders.filter(
        order => order.payments.length > 0 && order.purchasedPlan === null
      );

      logger.info(`[Purchased Plans] Found ${paymentOrdersWithoutPurchasedPlans.length} payment orders with completed payments but no purchased plans`);

      // Create PurchasedPlan records for these payment orders
      if (paymentOrdersWithoutPurchasedPlans.length > 0) {
        logger.info(`[Purchased Plans] Creating ${paymentOrdersWithoutPurchasedPlans.length} purchased plan records for user ${userId} (migration)`);
        
        for (const order of paymentOrdersWithoutPurchasedPlans) {
          try {
            if (!order.planId) {
              logger.warn(`[Purchased Plans] Skipping order ${order.id} - no planId`);
              continue;
            }

            // Check if a subscription already exists for this plan (if so, mark as ACTIVATED)
            const existingSubscription = await prisma.userSubscription.findFirst({
              where: {
                userId,
                planId: order.planId,
                status: 'ACTIVE',
              },
            });

            const purchasedPlanStatus = existingSubscription ? 'ACTIVATED' : 'PENDING';
            logger.info(`[Purchased Plans] Creating purchased plan for order ${order.id}, planId=${order.planId}, status=${purchasedPlanStatus}`);

            await prisma.purchasedPlan.create({
              data: {
                userId,
                planId: order.planId,
                paymentOrderId: order.id,
                status: purchasedPlanStatus,
                activatedAt: existingSubscription ? existingSubscription.createdAt : null,
                activatedSubscriptionId: existingSubscription?.id || null,
              },
            });

            logger.info(`[Purchased Plans] ✅ Created purchased plan for order ${order.id}`);
          } catch (error: any) {
            logger.error(`[Purchased Plans] ❌ Failed to create purchased plan for order ${order.id}:`, error);
            // Continue with other orders
          }
        }
      }

      // Now fetch all purchased plans
      const purchasedPlans = await prisma.purchasedPlan.findMany({
        where: {
          userId,
          status: 'PENDING', // Only show pending (not yet activated)
        },
        include: {
          plan: true,
          paymentOrder: {
            select: {
              id: true,
              amount: true,
              currency: true,
              status: true,
              createdAt: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      const response: ApiResponse = {
        success: true,
        data: purchasedPlans.map(pp => ({
          id: pp.id,
          planId: pp.planId,
          plan: {
            id: pp.plan.id,
            name: pp.plan.name,
            description: pp.plan.description,
            price: parseFloat(pp.plan.price.toString()),
            billingCycle: pp.plan.billingCycle,
            features: pp.plan.features,
          },
          status: pp.status,
          scheduledActivationDate: pp.scheduledActivationDate,
          createdAt: pp.createdAt,
          paymentOrder: pp.paymentOrder,
        })),
        message: 'Purchased plans retrieved successfully',
      };

      res.json(response);
    } catch (error: any) {
      logger.error('Error fetching purchased plans:', error);
      res.status(500).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve purchased plans',
          statusCode: 500,
        },
      });
    }
  }

  /**
   * Activate a purchased plan
   */
  @Post('/purchased/:id/activate')
  @Use(authenticate)
  async activatePurchasedPlan(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const { id } = req.params;

      // Get purchased plan
      const purchasedPlan = await prisma.purchasedPlan.findFirst({
        where: {
          id,
          userId,
          status: 'PENDING',
        },
        include: {
          plan: true,
        },
      });

      if (!purchasedPlan) {
        res.status(404).json({
          success: false,
          error: {
            message: 'Purchased plan not found or already activated',
            statusCode: 404,
          },
        });
        return;
      }

      // Deactivate all other active subscriptions first (only one active subscription at a time)
      await prisma.userSubscription.updateMany({
        where: {
          userId,
          status: 'ACTIVE',
          OR: [
            { endDate: null },
            { endDate: { gt: new Date() } },
          ],
        },
        data: {
          status: 'INACTIVE',
          updatedAt: new Date(),
        },
      });

      // Check if user already has a subscription for this plan (even if inactive)
      const existingSubscription = await prisma.userSubscription.findFirst({
        where: {
          userId,
          planId: purchasedPlan.planId,
        },
      });

      let subscription;
      if (existingSubscription) {
        // Reactivate and extend existing subscription
        const currentEndDate = existingSubscription.endDate || new Date();
        const newEndDate = this.calculateEndDate(currentEndDate, purchasedPlan.plan.billingCycle);

        subscription = await prisma.userSubscription.update({
          where: { id: existingSubscription.id },
          data: {
            status: 'ACTIVE',
            startDate: new Date(),
            endDate: newEndDate,
            updatedAt: new Date(),
            purchasedPlanId: purchasedPlan.id,
          },
          include: { plan: true },
        });
      } else {
        // Create new subscription
        const endDate = this.calculateEndDate(new Date(), purchasedPlan.plan.billingCycle);

        subscription = await prisma.userSubscription.create({
          data: {
            userId,
            planId: purchasedPlan.planId,
            status: 'ACTIVE',
            startDate: new Date(),
            endDate: endDate,
            autoRenew: true,
            paymentMethod: 'RAZORPAY',
            purchasedPlanId: purchasedPlan.id,
          },
          include: { plan: true },
        });
      }

      // Mark purchased plan as activated
      await prisma.purchasedPlan.update({
        where: { id },
        data: {
          status: 'ACTIVATED',
          activatedAt: new Date(),
          activatedSubscriptionId: subscription.id,
        },
      });

      const response: ApiResponse = {
        success: true,
        data: {
          subscription: {
            id: subscription.id,
            planId: subscription.planId,
            status: subscription.status,
            startDate: subscription.startDate,
            endDate: subscription.endDate,
            plan: {
              id: subscription.plan.id,
              name: subscription.plan.name,
              price: parseFloat(subscription.plan.price.toString()),
              billingCycle: subscription.plan.billingCycle,
            },
          },
        },
        message: 'Plan activated successfully',
      };

      res.json(response);
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: {
          message: error.message || 'Failed to activate purchased plan',
          statusCode: 500,
        },
      });
    }
  }

  /**
   * Calculate subscription end date based on billing cycle
   */
  private calculateEndDate(startDate: Date, billingCycle: string): Date | null {
    const endDate = new Date(startDate);
    switch (billingCycle) {
      case 'MONTHLY':
        endDate.setMonth(endDate.getMonth() + 1);
        return endDate;
      case 'YEARLY':
        endDate.setFullYear(endDate.getFullYear() + 1);
        return endDate;
      case 'LIFETIME':
        return null; // Lifetime plans have no end date
      default:
        endDate.setMonth(endDate.getMonth() + 1);
        return endDate;
    }
  }
}
