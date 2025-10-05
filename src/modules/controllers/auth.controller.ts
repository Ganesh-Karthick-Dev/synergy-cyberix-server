import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { UserService } from '../services/user.service';
import { CreateUserDto, LoginDto, RegisterUserDto } from '../dtos/user.dto';
import { ApiResponse } from '../../types';
import { CustomError } from '../../middlewares/error.middleware';

export class AuthController {
  private authService: AuthService;
  private userService: UserService;

  constructor() {
    this.authService = new AuthService();
    this.userService = new UserService();
  }

  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userData: CreateUserDto = req.body;
      
      const user = await this.userService.createUser(userData);
      const tokens = this.authService.generateTokens(user);

      const response: ApiResponse = {
        success: true,
        data: {
          user,
          ...tokens
        },
        message: 'User registered successfully'
      };

      res.status(201).json(response);
    } catch (error) {
      next(error);
    }
  }

  async registerUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const registerData: RegisterUserDto = req.body;
      
      const result = await this.userService.registerUser(registerData);

      const response: ApiResponse = {
        success: true,
        data: result,
        message: 'User registered successfully. Please check your email for login credentials.'
      };

      res.status(201).json(response);
    } catch (error) {
      next(error);
    }
  }

  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const credentials: LoginDto = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');
      
      const user = await this.userService.validateCredentials(credentials, ipAddress, userAgent);
      const tokens = this.authService.generateTokens(user);

      // Create session if remember me is enabled
      if (credentials.rememberMe) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30); // 30 days
        await this.userService.createSession(
          user.id,
          tokens.refreshToken,
          expiresAt,
          credentials.deviceInfo,
          ipAddress,
          userAgent
        );
      }

      const response: ApiResponse = {
        success: true,
        data: {
          user,
          ...tokens
        },
        message: 'Login successful'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async refreshToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new CustomError('Refresh token is required', 400);
      }

      const tokens = await this.authService.refreshTokens(refreshToken);

      const response: ApiResponse = {
        success: true,
        data: tokens,
        message: 'Token refreshed successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // In a real application, you would invalidate the refresh token
      // by removing it from the database or adding it to a blacklist

      const response: ApiResponse = {
        success: true,
        message: 'Logout successful'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async getProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const user = await this.userService.getUserById(req.user!.id);

      const response: ApiResponse = {
        success: true,
        data: { user },
        message: 'Profile retrieved successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async getActiveSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const sessions = await this.userService.getActiveSessions(req.user!.id);

      const response: ApiResponse = {
        success: true,
        data: { sessions },
        message: 'Active sessions retrieved successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async revokeSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { sessionId } = req.params;
      const userId = req.user!.id;

      if (!sessionId) {
        throw new CustomError('Session ID is required', 400);
      }

      await this.userService.revokeSession(sessionId, userId);

      const response: ApiResponse = {
        success: true,
        message: 'Session revoked successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async revokeAllSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;

      await this.userService.revokeAllSessions(userId);

      const response: ApiResponse = {
        success: true,
        message: 'All sessions revoked successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async forgotPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email } = req.body;

      // In a real application, you would send a password reset email
      // For now, we'll just return a success message
      const response: ApiResponse = {
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { token, newPassword } = req.body;

      // In a real application, you would validate the reset token
      // and update the password
      const response: ApiResponse = {
        success: true,
        message: 'Password reset successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }
}
