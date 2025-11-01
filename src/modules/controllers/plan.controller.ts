import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { PlanService } from '../services/plan.service';

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
    body('features').notEmpty().withMessage('Features are required'),
    body('deliveryDays').isNumeric().withMessage('Delivery days must be a number')
  ])
  async createPlan(req: Request, res: Response): Promise<void> {
    try {
      const { name, price, description, features, deliveryDays, isPopular = false, isActive = true } = req.body;

      const plan = await this.planService.createPlan({
        name,
        price: Number(price),
        description,
        features,
        deliveryDays: Number(deliveryDays),
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
}
