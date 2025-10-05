import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { UserService } from '../services/user.service';
import { ApiResponse } from '../../types';

@Service()
@Controller('/api/admin')
export class AdminController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  @Get('/users')
  async getAllUsers(req: Request, res: Response): Promise<void> {
    try {
      const { page = 1, limit = 10, search = '', status = '' } = req.query;
      
      const result = await this.userService.getAllUsers({
        page: Number(page),
        limit: Number(limit),
        search: search as string,
        status: status as string
      });

      const response: ApiResponse = {
        success: true,
        data: result,
        message: 'Users retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve users',
          statusCode: 500
        }
      });
    }
  }

  @Get('/users/:id')
  async getUserById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({
          success: false,
          error: { message: 'User ID is required', statusCode: 400 }
        });
        return;
      }

      const user = await this.userService.getUserById(id);
      const response: ApiResponse = {
        success: true,
        data: user,
        message: 'User retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve user',
          statusCode: 500
        }
      });
    }
  }

  @Put('/users/:id/status')
  async updateUserStatus(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!id) {
        res.status(400).json({
          success: false,
          error: { message: 'User ID is required', statusCode: 400 }
        });
        return;
      }

      if (!status || !['ACTIVE', 'INACTIVE', 'SUSPENDED'].includes(status)) {
        res.status(400).json({
          success: false,
          error: { message: 'Valid status is required (ACTIVE, INACTIVE, SUSPENDED)', statusCode: 400 }
        });
        return;
      }

      const user = await this.userService.updateUser(id, { status });
      const response: ApiResponse = {
        success: true,
        data: user,
        message: 'User status updated successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to update user status',
          statusCode: 500
        }
      });
    }
  }

  @Get('/dashboard/stats')
  async getDashboardStats(req: Request, res: Response): Promise<void> {
    try {
      // This would typically come from a stats service
      const stats = {
        totalUsers: 0,
        activeUsers: 0,
        newUsersToday: 0,
        totalSubscriptions: 0,
        freeSubscriptions: 0,
        proSubscriptions: 0,
        proPlusSubscriptions: 0
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
}
