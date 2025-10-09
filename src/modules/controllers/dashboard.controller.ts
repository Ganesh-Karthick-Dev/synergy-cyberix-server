import { Request, Response } from 'express';
import { Controller, Get } from '../../decorators/controller.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';

@Service()
@Controller('/api/dashboard')
export class DashboardController {
  @Get('/stats')
  async getDashboardStats(req: Request, res: Response): Promise<void> {
    try {
      const stats = {
        totalUsers: 1250,
        activeUsers: 1100,
        newUsersToday: 25,
        totalSubscriptions: 1250,
        freeSubscriptions: 800,
        proSubscriptions: 350,
        proPlusSubscriptions: 100,
        revenue: {
          monthly: 45000,
          yearly: 540000
        },
        growth: {
          users: 12.5,
          revenue: 8.3
        }
      };

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Dashboard stats retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve dashboard stats',
          statusCode: 500
        }
      });
    }
  }

  @Get('/recent-activity')
  async getRecentActivity(req: Request, res: Response): Promise<void> {
    try {
      const activities = [
        {
          id: '1',
          type: 'user_registration',
          message: 'New user registered: john.doe@company.com',
          timestamp: new Date().toISOString(),
          user: 'John Doe'
        },
        {
          id: '2',
          type: 'subscription_upgrade',
          message: 'User upgraded to PRO plan',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          user: 'Jane Smith'
        },
        {
          id: '3',
          type: 'security_scan',
          message: 'Security scan completed for domain: example.com',
          timestamp: new Date(Date.now() - 7200000).toISOString(),
          user: 'System'
        }
      ];

      const response: ApiResponse = {
        success: true,
        data: activities,
        message: 'Recent activity retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve recent activity',
          statusCode: 500
        }
      });
    }
  }

  @Get('/charts/revenue')
  async getRevenueChart(req: Request, res: Response): Promise<void> {
    try {
      const revenueData = {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [
          {
            label: 'Revenue',
            data: [12000, 15000, 18000, 22000, 19000, 25000],
            borderColor: 'rgb(59, 130, 246)',
            backgroundColor: 'rgba(59, 130, 246, 0.1)'
          }
        ]
      };

      const response: ApiResponse = {
        success: true,
        data: revenueData,
        message: 'Revenue chart data retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve revenue chart data',
          statusCode: 500
        }
      });
    }
  }

  @Get('/charts/users')
  async getUsersChart(req: Request, res: Response): Promise<void> {
    try {
      const usersData = {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [
          {
            label: 'New Users',
            data: [50, 75, 100, 125, 90, 150],
            borderColor: 'rgb(34, 197, 94)',
            backgroundColor: 'rgba(34, 197, 94, 0.1)'
          }
        ]
      };

      const response: ApiResponse = {
        success: true,
        data: usersData,
        message: 'Users chart data retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve users chart data',
          statusCode: 500
        }
      });
    }
  }
}


