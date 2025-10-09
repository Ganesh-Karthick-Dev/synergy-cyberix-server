import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';

@Service()
@Controller('/api/plans')
export class PlanController {
  @Get('/')
  async getAllPlans(req: Request, res: Response): Promise<void> {
    try {
      const { search, status, isPopular } = req.query;
      
      // Mock data based on plan-management/page.tsx structure
      const plans = [
        {
          id: '1',
          name: 'Basic Security Scan',
          price: 299,
          description: 'Comprehensive security assessment to identify vulnerabilities and protect your website from potential threats.',
          features: ['Basic vulnerability scan', 'SSL certificate check', 'Security headers analysis', 'Basic penetration testing', 'Detailed security report'],
          deliveryDays: 2,
          isPopular: false,
          isActive: true,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01'
        },
        {
          id: '2',
          name: 'Professional Security Audit',
          price: 799,
          description: 'Advanced security assessment with comprehensive vulnerability scanning and detailed remediation guidance.',
          features: ['Full vulnerability assessment', 'OWASP Top 10 analysis', 'SQL injection testing', 'XSS vulnerability scan', 'Security recommendations', 'Priority-based remediation'],
          deliveryDays: 5,
          isPopular: true,
          isActive: true,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01'
        },
        {
          id: '3',
          name: 'Enterprise Security Suite',
          price: 1499,
          description: 'Complete enterprise-grade security solution with continuous monitoring and advanced threat detection.',
          features: ['Comprehensive security audit', 'Advanced penetration testing', 'Code security analysis', 'API security testing', 'Continuous monitoring', '24/7 security support', 'Compliance reporting'],
          deliveryDays: 7,
          isPopular: false,
          isActive: true,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01'
        }
      ];

      // Apply filters
      let filteredPlans = plans;
      
      if (search) {
        const searchTerm = (search as string).toLowerCase();
        filteredPlans = filteredPlans.filter(plan => 
          plan.name.toLowerCase().includes(searchTerm) ||
          plan.description.toLowerCase().includes(searchTerm)
        );
      }
      
      if (status) {
        filteredPlans = filteredPlans.filter(plan => plan.isActive === (status === 'active'));
      }
      
      if (isPopular !== undefined) {
        filteredPlans = filteredPlans.filter(plan => plan.isPopular === (isPopular === 'true'));
      }

      const response: ApiResponse = {
        success: true,
        data: filteredPlans,
        message: 'Plans retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve plans',
          statusCode: 500
        }
      });
    }
  }

  @Post('/')
  @Validate([
    body('name').notEmpty().withMessage('Plan name is required'),
    body('price').isNumeric().withMessage('Price must be a number'),
    body('description').notEmpty().withMessage('Description is required'),
    body('features').isArray().withMessage('Features must be an array'),
    body('deliveryDays').isNumeric().withMessage('Delivery days must be a number')
  ])
  async createPlan(req: Request, res: Response): Promise<void> {
    try {
      const { name, price, description, features, deliveryDays, isPopular = false, isActive = true } = req.body;

      const newPlan = {
        id: Date.now().toString(),
        name,
        price: Number(price),
        description,
        features,
        deliveryDays: Number(deliveryDays),
        isPopular,
        isActive,
        createdAt: new Date().toISOString().split('T')[0],
        updatedAt: new Date().toISOString().split('T')[0]
      };

      const response: ApiResponse = {
        success: true,
        data: newPlan,
        message: 'Plan created successfully'
      };

      res.status(201).json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to create plan',
          statusCode: 500
        }
      });
    }
  }

  @Put('/:id')
  async updatePlan(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData = req.body;

      // Mock update - in real app, this would update database
      const updatedPlan = {
        id,
        ...updateData,
        updatedAt: new Date().toISOString().split('T')[0]
      };

      const response: ApiResponse = {
        success: true,
        data: updatedPlan,
        message: 'Plan updated successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to update plan',
          statusCode: 500
        }
      });
    }
  }

  @Delete('/:id')
  async deletePlan(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // Mock deletion - in real app, this would delete from database
      const response: ApiResponse = {
        success: true,
        message: 'Plan deleted successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to delete plan',
          statusCode: 500
        }
      });
    }
  }
}
