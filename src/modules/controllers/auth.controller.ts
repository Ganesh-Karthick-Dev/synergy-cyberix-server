import { Request, Response } from 'express';
import { Controller, Post, Get, Delete } from '../../decorators/controller.decorator';
import { Validate, RegisterUserValidation } from '../../decorators/validation.decorator';
import { body } from 'express-validator';
import { Service } from '../../decorators/service.decorator';
import { UserService } from '../services/user.service';
import { AuthService } from '../services/auth.service';
import { ApiResponse } from '../../types';

@Service()
@Controller('/api/auth')
export class AuthController {
  private userService: UserService;
  private authService: AuthService;

  constructor() {
    this.userService = new UserService();
    this.authService = new AuthService();
  }

  @Post('/login')
  @Validate([
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
  ])
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;
      
      const user = await this.userService.validateCredentials({ email, password });
      if (!user) {
        res.status(401).json({
          success: false,
          error: { message: 'Invalid credentials', statusCode: 401 }
        });
        return;
      }

      const tokens = this.authService.generateTokens({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        isActive: user.isActive
      });

      const response: ApiResponse = {
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            isActive: user.isActive
          },
          ...tokens
        },
        message: 'Login successful'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Login failed',
          statusCode: 500
        }
      });
    }
  }

  @Post('/logout')
  async logout(req: Request, res: Response): Promise<void> {
    try {
      // In a real app, you'd invalidate the token
      const response: ApiResponse = {
        success: true,
        message: 'Logout successful'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Logout failed',
          statusCode: 500
        }
      });
    }
  }

  @Get('/profile')
  async getProfile(req: Request, res: Response): Promise<void> {
    try {
      // This would typically get user from JWT token
      const userId = req.headers['x-user-id'] as string;
      if (!userId) {
        res.status(401).json({
          success: false,
          error: { message: 'Unauthorized', statusCode: 401 }
        });
        return;
      }

      const user = await this.userService.getUserById(userId);
      const response: ApiResponse = {
        success: true,
        data: user,
        message: 'Profile retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve profile',
          statusCode: 500
        }
      });
    }
  }

  @Post('/refresh-token')
  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;
      
      // In a real app, you'd validate the refresh token
      const response: ApiResponse = {
        success: true,
        data: { accessToken: 'new-access-token' },
        message: 'Token refreshed successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Token refresh failed',
          statusCode: 500
        }
      });
    }
  }
}