import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/user.service';
import { UpdateUserDto, ChangePasswordDto } from '../dtos/user.dto';
import { ApiResponse, SearchQuery } from '../../types';
import { CustomError } from '../../middlewares/error.middleware';

export class UserController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
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

  async updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userData: UpdateUserDto = req.body;
      const userId = req.user!.id;

      const user = await this.userService.updateUser(userId, userData);

      const response: ApiResponse = {
        success: true,
        data: { user },
        message: 'Profile updated successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const passwordData: ChangePasswordDto = req.body;
      const userId = req.user!.id;

      const result = await this.userService.changePassword(userId, passwordData);

      const response: ApiResponse = {
        success: true,
        data: result,
        message: 'Password changed successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async deleteAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;

      await this.userService.deleteUser(userId);

      const response: ApiResponse = {
        success: true,
        message: 'Account deleted successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async getAllUsers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const query: SearchQuery = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 10,
        search: req.query.search as string
      };

      const result = await this.userService.getAllUsers(
        query.page,
        query.limit,
        query.search
      );

      const response: ApiResponse = {
        success: true,
        data: result.users,
        pagination: result.pagination,
        message: 'Users retrieved successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }

  async getUserById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        throw new CustomError('User ID is required', 400);
      }

      const user = await this.userService.getUserById(id);

      const response: ApiResponse = {
        success: true,
        data: { user },
        message: 'User retrieved successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }
}
