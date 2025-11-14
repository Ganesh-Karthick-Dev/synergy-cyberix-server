import { Request, Response } from 'express';
import { Controller, Get, Post, Put } from '../../decorators/controller.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { SecurityToolsService } from '../services/security-tools.service';
import { SecurityCategory } from '@prisma/client';

@Service()
@Controller('/api/security-tools')
export class SecurityToolsController {
  private securityToolsService: SecurityToolsService;

  constructor() {
    this.securityToolsService = new SecurityToolsService();
  }

  @Get('/')
  async getAllTools(req: Request, res: Response): Promise<void> {
    try {
      const { category, search, status } = req.query;

      const filters: any = {};

      if (category && category !== 'all') {
        filters.category = category as SecurityCategory;
      }

      if (search) {
        filters.search = search as string;
      }

      if (status) {
        filters.status = status as 'active' | 'inactive';
      }

      const tools = await this.securityToolsService.getAllTools(filters);

      // Transform to frontend format
      const transformedTools = tools.map(tool => ({
        id: tool.id,
        name: tool.name,
        description: tool.description,
        category: tool.category.toLowerCase(),
        isEnabled: tool.isActive,
        status: tool.isActive ? 'active' : 'maintenance',
        lastUpdated: this.getTimeAgo(tool.updatedAt),
        config: tool.config
      }));

      const response: ApiResponse = {
        success: true,
        data: transformedTools,
        message: 'Security tools retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve security tools',
          statusCode: 500
        }
      });
    }
  }

  @Get('/categories')
  async getToolCategories(req: Request, res: Response): Promise<void> {
    try {
      const categories = await this.securityToolsService.getToolCategories();

      const response: ApiResponse = {
        success: true,
        data: categories,
        message: 'Tool categories retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve tool categories',
          statusCode: 500
        }
      });
    }
  }

  @Put('/:id/toggle')
  async toggleTool(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { isEnabled } = req.body;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Tool ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const updatedTool = await this.securityToolsService.toggleTool(id, isEnabled);

      const response: ApiResponse = {
        success: true,
        data: {
          id: updatedTool.id,
          isEnabled: updatedTool.isActive,
          status: updatedTool.isActive ? 'active' : 'maintenance'
        },
        message: `Tool ${isEnabled ? 'enabled' : 'disabled'} successfully`
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to toggle tool',
          statusCode: 500
        }
      });
    }
  }

  @Post('/deploy-updates')
  async deployUpdates(req: Request, res: Response): Promise<void> {
    try {
      await this.securityToolsService.deployUpdates();

      const response: ApiResponse = {
        success: true,
        message: 'Security tools updates deployed successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to deploy updates',
          statusCode: 500
        }
      });
    }
  }

  @Get('/status')
  async getToolsStatus(req: Request, res: Response): Promise<void> {
    try {
      const toolStatuses = await this.securityToolsService.getToolsStatus();

      const response: ApiResponse = {
        success: true,
        data: toolStatuses,
        message: 'Tool statuses retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve tool statuses',
          statusCode: 500
        }
      });
    }
  }

  private getTimeAgo(date: Date): string {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffHours < 1) {
      return 'Just now';
    } else if (diffHours < 24) {
      return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
      return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    } else {
      return `${Math.floor(diffDays / 7)} week${Math.floor(diffDays / 7) > 1 ? 's' : ''} ago`;
    }
  }
}
