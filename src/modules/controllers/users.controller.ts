import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body, query } from 'express-validator';
import { UserService } from '../services/user.service';
import { prisma } from '../../config/db';
import { UserRole } from '@prisma/client';

@Service()
@Controller('/api/users')
export class UsersController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  @Get('/')
  async getAllUsers(req: Request, res: Response): Promise<void> {
    try {
      const { page = 1, limit = 10, search, status, plan } = req.query;
      
      // Get users from database using UserService
      const result = await this.userService.getAllUsers(
        Number(page),
        Number(limit),
        search as string | undefined,
        status as string | undefined,
        plan as string | undefined
      );

      const response: ApiResponse = {
        success: true,
        data: {
          users: result.users,
          total: result.pagination.total,
          page: result.pagination.page,
          limit: result.pagination.limit,
          totalPages: result.pagination.totalPages
        },
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

  @Get('/:id')
  async getUserById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      
      // Get user from database
      const user = await prisma.user.findUnique({
        where: { id },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          avatar: true,
          phone: true,
          role: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
          subscriptions: {
            where: { status: 'ACTIVE' },
            include: {
              plan: {
                select: {
                  name: true,
                  id: true
                }
              }
            },
            orderBy: { createdAt: 'desc' },
            take: 1
          },
          _count: {
            select: {
              securityReports: true
            }
          }
        }
      });

      if (!user) {
        res.status(404).json({
          success: false,
          error: {
            message: 'User not found',
            statusCode: 404
          }
        });
        return;
      }

      // Transform user to match frontend format (same logic as getAllUsers)
      const activeSubscription = user.subscriptions[0];
      const planName = activeSubscription?.plan?.name || 'Free';
      
      const statusMap: { [key: string]: string } = {
        'ACTIVE': 'Active',
        'INACTIVE': 'Inactive',
        'SUSPENDED': 'Inactive',
        'PENDING': 'Trial'
      };
      
      const name = [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email.split('@')[0];

      let lastScan = 'Never';
      if (user.lastLoginAt) {
        const now = new Date();
        const lastLogin = new Date(user.lastLoginAt);
        const diffMs = now.getTime() - lastLogin.getTime();
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffHours < 1) {
          lastScan = 'Just now';
        } else if (diffHours < 24) {
          lastScan = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
          lastScan = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        } else {
          lastScan = `${Math.floor(diffDays / 7)} week${Math.floor(diffDays / 7) > 1 ? 's' : ''} ago`;
        }
      }

      const transformedUser = {
        id: user.id,
        email: user.email,
        name: name,
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        avatar: user.avatar || null,
        phone: user.phone || null,
        role: user.role,
        status: statusMap[user.status] || 'Active',
        plan: planName,
        lastScan: lastScan,
        scansCompleted: user._count.securityReports,
        location: null,
        bio: null,
        company: null,
        createdAt: user.createdAt.toISOString(),
        updatedAt: user.updatedAt.toISOString()
      };

      const response: ApiResponse = {
        success: true,
        data: transformedUser,
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

  @Put('/:id')
  @Validate([
    body('firstName').optional().isString().withMessage('First name must be a string'),
    body('lastName').optional().isString().withMessage('Last name must be a string'),
    body('email').optional().isEmail().withMessage('Email must be valid'),
    body('phone').optional().isString().withMessage('Phone must be a string'),
    body('avatar').optional().isString().withMessage('Avatar must be a string')
  ])
  async updateUser(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { firstName, lastName, email, phone, avatar } = req.body;

      // Check if user exists
      const existingUser = await prisma.user.findUnique({
        where: { id }
      });

      if (!existingUser) {
        res.status(404).json({
          success: false,
          error: {
            message: 'User not found',
            statusCode: 404
          }
        });
        return;
      }

      // Check if email is being changed and if it's already taken
      if (email && email !== existingUser.email) {
        const emailExists = await prisma.user.findUnique({
          where: { email }
        });
        if (emailExists) {
          res.status(400).json({
            success: false,
            error: {
              message: 'Email already exists',
              statusCode: 400
            }
          });
          return;
        }
      }

      // Update user in database
      const updatedUser = await prisma.user.update({
        where: { id },
        data: {
          ...(firstName !== undefined && { firstName }),
          ...(lastName !== undefined && { lastName }),
          ...(email !== undefined && { email }),
          ...(phone !== undefined && { phone }),
          ...(avatar !== undefined && { avatar })
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          avatar: true,
          phone: true,
          role: true,
          status: true,
          updatedAt: true
        }
      });

      const response: ApiResponse = {
        success: true,
        data: updatedUser,
        message: 'User updated successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to update user',
          statusCode: 500
        }
      });
    }
  }

  @Put('/:id/status')
  @Validate([
    body('status').isIn(['Active', 'Inactive', 'Trial', 'Expired']).withMessage('Invalid status')
  ])
  async updateUserStatus(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body;

      // Check if user exists
      const existingUser = await prisma.user.findUnique({
        where: { id }
      });

      if (!existingUser) {
        res.status(404).json({
          success: false,
          error: {
            message: 'User not found',
            statusCode: 404
          }
        });
        return;
      }

      // Map frontend status to database status
      const statusMap: { [key: string]: string } = {
        'Active': 'ACTIVE',
        'Inactive': 'INACTIVE',
        'Trial': 'ACTIVE',
        'Expired': 'INACTIVE'
      };

      const dbStatus = statusMap[status] || status.toUpperCase();

      // Update user status in database
      const updatedUser = await prisma.user.update({
        where: { id },
        data: {
          status: dbStatus as any
        },
        select: {
          id: true,
          status: true,
          updatedAt: true
        }
      });

      const response: ApiResponse = {
        success: true,
        data: {
          id: updatedUser.id,
          status: status // Return frontend format status
        },
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

  @Delete('/:id')
  async deleteUser(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // Check if user exists
      const existingUser = await prisma.user.findUnique({
        where: { id }
      });

      if (!existingUser) {
        res.status(404).json({
          success: false,
          error: {
            message: 'User not found',
            statusCode: 404
          }
        });
        return;
      }

      // Delete user from database (cascade will handle related records)
      await prisma.user.delete({
        where: { id }
      });

      const response: ApiResponse = {
        success: true,
        message: 'User deleted successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to delete user',
          statusCode: 500
        }
      });
    }
  }

  @Get('/stats/overview')
  async getUserStats(req: Request, res: Response): Promise<void> {
    try {
      // Get statistics from database - exclude ADMIN users (only regular users)
      const userWhere = { role: UserRole.USER };
      const [
        totalUsers,
        activeUsers,
        inactiveUsers,
        newUsersToday,
        totalScans,
        usersWithSubscriptions
      ] = await Promise.all([
        prisma.user.count({ where: userWhere }),
        prisma.user.count({ where: { ...userWhere, status: 'ACTIVE' } }),
        prisma.user.count({ where: { ...userWhere, status: 'INACTIVE' } }),
        prisma.user.count({
          where: {
            ...userWhere,
            createdAt: {
              gte: new Date(new Date().setHours(0, 0, 0, 0))
            }
          }
        }),
        prisma.securityReport.count({
          where: {
            user: {
              role: UserRole.USER
            }
          }
        }),
        prisma.userSubscription.count({ 
          where: { 
            status: 'ACTIVE',
            user: {
              role: UserRole.USER
            }
          } 
        })
      ]);

      // Calculate average scans per user
      const averageScansPerUser = totalUsers > 0 ? totalScans / totalUsers : 0;

      const stats = {
        totalUsers,
        activeUsers,
        trialUsers: usersWithSubscriptions, // Users with active subscriptions
        expiredUsers: inactiveUsers,
        newUsersToday,
        totalScansCompleted: totalScans,
        averageScansPerUser: Math.round(averageScansPerUser * 10) / 10 // Round to 1 decimal
      };

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'User statistics retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve user statistics',
          statusCode: 500
        }
      });
    }
  }
}


