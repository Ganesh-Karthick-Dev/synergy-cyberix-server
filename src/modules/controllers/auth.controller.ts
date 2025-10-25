import { Request, Response } from 'express';
import { Controller, Post, Get, Delete } from '../../decorators/controller.decorator';
import { Validate, RegisterUserValidation } from '../../decorators/validation.decorator';
import { body } from 'express-validator';
import { Service } from '../../decorators/service.decorator';
import { UserService } from '../services/user.service';
import { AuthService } from '../services/auth.service';
import { NotificationService } from '../services/notification.service';
import { ApiResponse } from '../../types';
import { authenticate } from '../../middlewares/auth.middleware';
import { prisma } from '../../config/db';
import { Use } from '../../decorators/middleware.decorator';

@Service()
@Controller('/api/auth')
export class AuthController {
  private userService: UserService;
  private authService: AuthService;
  private notificationService: NotificationService;

  constructor() {
    this.userService = new UserService();
    this.authService = new AuthService();
    this.notificationService = new NotificationService();
  }

  @Post('/login')
  @Validate([
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
  ])
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, deviceInfo } = req.body;

      console.log('req.body', req.body);
      
      const user = await this.userService.validateCredentials({ email, password });
      if (!user) {
        // Log failed login attempt
        await this.authService.logLoginAttempt(
          '', // No userId for failed attempts
          email,
          false,
          req.ip,
          req.get('User-Agent'),
          'Invalid credentials'
        );
        
        res.status(401).json({
          success: false,
          error: { message: 'Invalid credentials', statusCode: 401 }
        });
        return;
      }

      // Check if user already has an active session
      const existingSessions = await this.authService.getUserSessions(user.id);
      if (existingSessions.length > 0) {
        // Log failed login attempt due to existing session
        await this.authService.logLoginAttempt(
          user.id,
          email,
          false,
          req.ip,
          req.get('User-Agent'),
          'User already logged in on another device'
        );
        
        res.status(409).json({
          success: false,
          error: { 
            message: 'Another user is already logged in with this account. Please logout from other devices first or contact support.', 
            statusCode: 409,
            code: 'USER_ALREADY_LOGGED_IN'
          }
        });
        return;
      }

      const tokens = this.authService.generateTokens({
        id: user.id,
        email: user.email,
        role: user.role,
        isActive: user.isActive
      });

      // Create new session (this will invalidate all previous sessions)
      await this.authService.createSession(
        user.id,
        tokens.accessToken,
        deviceInfo,
        req.ip,
        req.get('User-Agent')
      );

      // Send login notification to user about new device login
      try {
        await this.notificationService.sendLoginNotification({
          userId: user.id,
          newDeviceInfo: deviceInfo || 'Unknown Device',
          newIpAddress: req.ip || 'Unknown IP',
          newUserAgent: req.get('User-Agent') || 'Unknown User Agent',
          timestamp: new Date()
        });
      } catch (notificationError) {
        // Log notification error but don't fail the login
        console.error('Failed to send login notification:', notificationError);
      }

      // Set cookies for tokens
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      // Log successful login attempt
      await this.authService.logLoginAttempt(
        user.id,
        user.email,
        true,
        req.ip,
        req.get('User-Agent'),
        'Login successful'
      );

      const response: ApiResponse = {
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive
          }
        },
        message: 'Login successful. Previous sessions have been invalidated.'
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
      const accessToken = req.cookies.accessToken;
      let userId = '';
      
      if (accessToken) {
        // Get user info before invalidating session
        try {
          const payload = this.authService.verifyAccessToken(accessToken);
          userId = payload.userId;
        } catch (error) {
          // Token is invalid, continue with logout
        }
        
        // Invalidate the session
        await this.authService.invalidateSession(accessToken);
      }

      // Log logout attempt
      if (userId) {
        await this.authService.logLoginAttempt(
          userId,
          '', // Email not available in logout
          true,
          req.ip,
          req.get('User-Agent'),
          'User logout'
        );
      }

      // Clear cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');

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

  @Post('/refresh')
  async refresh(req: Request, res: Response): Promise<void> {
    try {
      const refreshToken = req.cookies.refreshToken;

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          error: { message: 'Refresh token not found', statusCode: 401 }
        });
        return;
      }

      const tokens = await this.authService.refreshTokens(refreshToken);

      // Set new cookies
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      const response: ApiResponse = {
        success: true,
        message: 'Tokens refreshed successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(401).json({
        success: false,
        error: {
          message: 'Invalid refresh token',
          statusCode: 401
        }
      });
    }
  }

  @Get('/notifications')
  @Use(authenticate)
  async getNotifications(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      const limit = parseInt(req.query.limit as string) || 10;
      const notifications = await this.notificationService.getUserNotifications(req.user.id, limit);
      const stats = await this.notificationService.getNotificationStats(req.user.id);

      const response: ApiResponse = {
        success: true,
        data: {
          notifications,
          stats
        },
        message: 'Notifications retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to get notifications',
          statusCode: 500
        }
      });
    }
  }

  @Post('/notifications/:id/read')
  @Use(authenticate)
  async markNotificationAsRead(req: Request, res: Response): Promise<void> {
    try {
      const notificationId = req.params.id;

      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      if (!notificationId) {
        res.status(400).json({
          success: false,
          error: { message: 'Notification ID is required', statusCode: 400 }
        });
        return;
      }

      await this.notificationService.markNotificationAsRead(notificationId, req.user.id);

      const response: ApiResponse = {
        success: true,
        message: 'Notification marked as read'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to mark notification as read',
          statusCode: 500
        }
      });
    }
  }

  @Post('/notifications/read-all')
  @Use(authenticate)
  async markAllNotificationsAsRead(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      await this.notificationService.markAllNotificationsAsRead(req.user.id);

      const response: ApiResponse = {
        success: true,
        message: 'All notifications marked as read'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to mark all notifications as read',
          statusCode: 500
        }
      });
    }
  }

  @Get('/notifications/stream')
  @Use(authenticate)
  async getNotificationStream(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Set SSE headers
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Cache-Control'
      });

      // Send initial connection message
      res.write(`data: ${JSON.stringify({
        type: 'connected',
        message: 'Notification stream connected',
        timestamp: new Date().toISOString()
      })}\n\n`);

      // Keep connection alive with periodic ping
      const pingInterval = setInterval(() => {
        res.write(`data: ${JSON.stringify({
          type: 'ping',
          timestamp: new Date().toISOString()
        })}\n\n`);
      }, 30000); // Ping every 30 seconds

      // Handle client disconnect
      const userId = req.user.id;
      req.on('close', () => {
        clearInterval(pingInterval);
        console.log(`Notification stream closed for user ${userId}`);
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to establish notification stream',
          statusCode: 500
        }
      });
    }
  }

  @Get('/profile')
  @Use(authenticate)
  async getProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Unauthorized', statusCode: 401 }
        });
        return;
      }

      const user = await this.userService.getUserById(req.user.id);
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

  @Post('/logout-all')
  @Use(authenticate)
  async logoutAllDevices(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Invalidate all sessions for this user
      await this.authService.invalidateAllUserSessions(req.user.id);

      // Clear current session cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');

      const response: ApiResponse = {
        success: true,
        message: 'Logged out from all devices successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to logout from all devices',
          statusCode: 500
        }
      });
    }
  }

  @Get('/login-logs')
  @Use(authenticate)
  async getLoginLogs(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: { message: 'Authentication required', statusCode: 401 }
        });
        return;
      }

      // Only allow admin users to view all login logs
      if (req.user.role !== 'ADMIN' && req.user.role !== 'SUPER_ADMIN') {
        res.status(403).json({
          success: false,
          error: { message: 'Access denied. Admin privileges required.', statusCode: 403 }
        });
        return;
      }

      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;
      const skip = (page - 1) * limit;

      const [logs, total] = await Promise.all([
        prisma.loginLog.findMany({
          skip,
          take: limit,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true
              }
            }
          }
        }),
        prisma.loginLog.count()
      ]);

      const response: ApiResponse = {
        success: true,
        data: {
          logs,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
          }
        },
        message: 'Login logs retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve login logs',
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