import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Use } from '../../decorators/middleware.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { ProjectService } from '../services/project.service';
import { PlanRestrictionService } from '../services/plan-restriction.service';
import { authenticate } from '../../middlewares/auth.middleware';

@Service()
@Controller('/api/projects')
export class ProjectController {
  private projectService: ProjectService;
  private planRestrictionService: PlanRestrictionService;

  constructor() {
    this.projectService = new ProjectService();
    this.planRestrictionService = new PlanRestrictionService();
  }

  /**
   * Create a new project
   */
  @Post('/')
  @Use(authenticate)
  @Validate([
    body('name').notEmpty().withMessage('Project name is required'),
    body('description').optional().isString().withMessage('Description must be a string'),
    body('target').optional().isString().withMessage('Target must be a string')
  ])
  async createProject(req: Request, res: Response): Promise<void> {
    try {
      const { name, description, target } = req.body;
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const project = await this.projectService.createProject(userId, {
        name,
        description,
        target
      });

      const response: ApiResponse = {
        success: true,
        data: project,
        message: 'Project created successfully'
      };

      res.status(201).json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to create project',
          statusCode
        }
      });
    }
  }

  /**
   * Get all projects for authenticated user
   */
  @Get('/')
  @Use(authenticate)
  async getUserProjects(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      const includeArchived = req.query.includeArchived === 'true';

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const projects = await this.projectService.getUserProjects(userId, includeArchived);

      const response: ApiResponse = {
        success: true,
        data: projects,
        message: 'Projects retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve projects',
          statusCode
        }
      });
    }
  }

  /**
   * Get a single project by ID
   */
  @Get('/:id')
  @Use(authenticate)
  async getProjectById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Project ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const project = await this.projectService.getProjectById(id, userId);

      const response: ApiResponse = {
        success: true,
        data: project,
        message: 'Project retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 404;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Project not found',
          statusCode
        }
      });
    }
  }

  /**
   * Update a project
   */
  @Put('/:id')
  @Use(authenticate)
  @Validate([
    body('name').optional().notEmpty().withMessage('Project name cannot be empty'),
    body('description').optional().isString().withMessage('Description must be a string'),
    body('target').optional().isString().withMessage('Target must be a string'),
    body('status').optional().isIn(['ACTIVE', 'ARCHIVED', 'DELETED']).withMessage('Invalid status')
  ])
  async updateProject(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { name, description, target, status } = req.body;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Project ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const project = await this.projectService.updateProject(id, userId, {
        name,
        description,
        target,
        status: status as 'ACTIVE' | 'ARCHIVED' | 'DELETED' | undefined
      });

      const response: ApiResponse = {
        success: true,
        data: project,
        message: 'Project updated successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to update project',
          statusCode
        }
      });
    }
  }

  /**
   * Delete a project
   */
  @Delete('/:id')
  @Use(authenticate)
  async deleteProject(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Project ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      await this.projectService.deleteProject(id, userId);

      const response: ApiResponse = {
        success: true,
        data: null,
        message: 'Project deleted successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to delete project',
          statusCode
        }
      });
    }
  }

  /**
   * Get project statistics
   */
  @Get('/:id/stats')
  @Use(authenticate)
  async getProjectStats(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Project ID is required',
            statusCode: 400
          }
        });
        return;
      }

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const stats = await this.projectService.getProjectStats(id, userId);

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Project statistics retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve project statistics',
          statusCode
        }
      });
    }
  }

  /**
   * Get user's plan information with usage
   */
  @Get('/plan/info')
  @Use(authenticate)
  async getUserPlanInfo(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          error: {
            message: 'User not authenticated',
            statusCode: 401
          }
        });
        return;
      }

      const planInfo = await this.planRestrictionService.getUserPlanInfo(userId);

      const response: ApiResponse = {
        success: true,
        data: planInfo,
        message: 'Plan information retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve plan information',
          statusCode
        }
      });
    }
  }
}
