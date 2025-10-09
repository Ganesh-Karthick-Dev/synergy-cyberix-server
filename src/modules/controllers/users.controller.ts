import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body, query } from 'express-validator';

@Service()
@Controller('/api/users')
export class UsersController {
  @Get('/')
  async getAllUsers(req: Request, res: Response): Promise<void> {
    try {
      const { page = 1, limit = 10, search, status, plan } = req.query;
      
      // Mock data based on UsersTable.tsx structure
      const users = [
        {
          id: 1,
          name: "John Smith",
          email: "john.smith@techcorp.com",
          company: "TechCorp Solutions",
          plan: "Professional",
          status: "Active",
          lastScan: "2 hours ago",
          scansCompleted: 45,
          avatar: "/images/user/user-17.jpg",
          phone: "+1 (555) 123-4567",
          location: "New York, USA",
          bio: "IT Security Manager at TechCorp",
          createdAt: "2024-01-15T10:30:00Z",
          updatedAt: "2024-01-20T14:22:00Z"
        },
        {
          id: 2,
          name: "Sarah Johnson",
          email: "sarah.j@startup.io",
          company: "StartupIO",
          plan: "Trial",
          status: "Trial",
          lastScan: "1 day ago",
          scansCompleted: 8,
          avatar: "/images/user/user-18.jpg",
          phone: "+1 (555) 234-5678",
          location: "San Francisco, USA",
          bio: "Founder & CTO at StartupIO",
          createdAt: "2024-01-18T09:15:00Z",
          updatedAt: "2024-01-19T16:45:00Z"
        },
        {
          id: 3,
          name: "Mike Chen",
          email: "mike.chen@enterprise.com",
          company: "Enterprise Systems",
          plan: "Enterprise",
          status: "Active",
          lastScan: "3 hours ago",
          scansCompleted: 127,
          avatar: "/images/user/user-19.jpg",
          phone: "+1 (555) 345-6789",
          location: "Seattle, USA",
          bio: "Senior Security Engineer",
          createdAt: "2024-01-10T14:20:00Z",
          updatedAt: "2024-01-21T11:30:00Z"
        },
        {
          id: 4,
          name: "Emily Davis",
          email: "emily.davis@freelance.com",
          company: "Freelance Consultant",
          plan: "Basic",
          status: "Expired",
          lastScan: "1 week ago",
          scansCompleted: 23,
          avatar: "/images/user/user-20.jpg",
          phone: "+1 (555) 456-7890",
          location: "Austin, USA",
          bio: "Independent Security Consultant",
          createdAt: "2024-01-05T16:45:00Z",
          updatedAt: "2024-01-15T09:20:00Z"
        },
        {
          id: 5,
          name: "Alex Rodriguez",
          email: "alex.r@agency.com",
          company: "Digital Security Agency",
          plan: "Professional",
          status: "Active",
          lastScan: "30 minutes ago",
          scansCompleted: 89,
          avatar: "/images/user/user-21.jpg",
          phone: "+1 (555) 567-8901",
          location: "Miami, USA",
          bio: "Security Agency Director",
          createdAt: "2024-01-12T13:10:00Z",
          updatedAt: "2024-01-21T15:45:00Z"
        }
      ];

      // Apply filters
      let filteredUsers = users;
      
      if (search) {
        const searchTerm = (search as string).toLowerCase();
        filteredUsers = filteredUsers.filter(user => 
          user.name.toLowerCase().includes(searchTerm) ||
          user.email.toLowerCase().includes(searchTerm) ||
          user.company.toLowerCase().includes(searchTerm)
        );
      }
      
      if (status) {
        filteredUsers = filteredUsers.filter(user => user.status === status);
      }
      
      if (plan) {
        filteredUsers = filteredUsers.filter(user => user.plan === plan);
      }

      // Apply pagination
      const startIndex = (Number(page) - 1) * Number(limit);
      const endIndex = startIndex + Number(limit);
      const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

      const response: ApiResponse = {
        success: true,
        data: {
          users: paginatedUsers,
          total: filteredUsers.length,
          page: Number(page),
          limit: Number(limit),
          totalPages: Math.ceil(filteredUsers.length / Number(limit))
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
      
      // Mock user data
      const user = {
        id: Number(id),
        name: "John Smith",
        email: "john.smith@techcorp.com",
        company: "TechCorp Solutions",
        plan: "Professional",
        status: "Active",
        lastScan: "2 hours ago",
        scansCompleted: 45,
        avatar: "/images/user/user-17.jpg",
        phone: "+1 (555) 123-4567",
        location: "New York, USA",
        bio: "IT Security Manager at TechCorp",
        createdAt: "2024-01-15T10:30:00Z",
        updatedAt: "2024-01-20T14:22:00Z"
      };

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

  @Put('/:id')
  @Validate([
    body('name').optional().isString().withMessage('Name must be a string'),
    body('email').optional().isEmail().withMessage('Email must be valid'),
    body('company').optional().isString().withMessage('Company must be a string'),
    body('phone').optional().isString().withMessage('Phone must be a string'),
    body('location').optional().isString().withMessage('Location must be a string'),
    body('bio').optional().isString().withMessage('Bio must be a string')
  ])
  async updateUser(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData = req.body;

      // Mock update
      const updatedUser = {
        id: Number(id),
        ...updateData,
        updatedAt: new Date().toISOString()
      };

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

      // Mock status update
      const updatedUser = {
        id: Number(id),
        status,
        updatedAt: new Date().toISOString()
      };

      const response: ApiResponse = {
        success: true,
        data: updatedUser,
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

      // Mock deletion
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
      const stats = {
        totalUsers: 1250,
        activeUsers: 1100,
        trialUsers: 100,
        expiredUsers: 50,
        newUsersToday: 25,
        totalScansCompleted: 15420,
        averageScansPerUser: 12.3
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


