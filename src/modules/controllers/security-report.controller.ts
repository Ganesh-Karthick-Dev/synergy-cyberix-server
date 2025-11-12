import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Use } from '../../decorators/middleware.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { SecurityReportService } from '../services/security-report.service';
import { authenticate } from '../../middlewares/auth.middleware';
import { checkScanLimit } from '../../middlewares/plan-restriction.middleware';

@Service()
@Controller('/api/security-reports')
export class SecurityReportController {
  private reportService: SecurityReportService;

  constructor() {
    this.reportService = new SecurityReportService();
  }

  /**
   * Create a new security report (scan result)
   */
  @Post('/')
  @Use(authenticate)
  @Use(checkScanLimit)
  @Validate([
    body('toolId').notEmpty().withMessage('Tool ID is required'),
    body('title').notEmpty().withMessage('Report title is required'),
    body('content').notEmpty().withMessage('Report content is required'),
    body('projectId').optional().isString().withMessage('Project ID must be a string'),
    body('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid severity level'),
    body('status').optional().isIn(['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']).withMessage('Invalid status')
  ])
  async createReport(req: Request, res: Response): Promise<void> {
    try {
      const { projectId, toolId, title, content, severity, status, metadata } = req.body;
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

      const report = await this.reportService.createReport(userId, {
        projectId,
        toolId,
        title,
        content,
        severity,
        status,
        metadata
      });

      const response: ApiResponse = {
        success: true,
        data: report,
        message: 'Security report created successfully'
      };

      res.status(201).json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to create security report',
          statusCode
        }
      });
    }
  }

  /**
   * Get all reports for authenticated user
   */
  @Get('/')
  @Use(authenticate)
  async getUserReports(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      const { projectId, toolId, status, severity } = req.query;

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

      const reports = await this.reportService.getUserReports(userId, {
        projectId: projectId as string,
        toolId: toolId as string,
        status: status as string,
        severity: severity as string
      });

      const response: ApiResponse = {
        success: true,
        data: reports,
        message: 'Security reports retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve security reports',
          statusCode
        }
      });
    }
  }

  /**
   * Get reports for a specific project
   */
  @Get('/project/:projectId')
  @Use(authenticate)
  async getProjectReports(req: Request, res: Response): Promise<void> {
    try {
      const { projectId } = req.params;
      const userId = req.user?.id;

      if (!projectId) {
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

      const reports = await this.reportService.getProjectReports(projectId, userId);

      const response: ApiResponse = {
        success: true,
        data: reports,
        message: 'Project reports retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 404;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve project reports',
          statusCode
        }
      });
    }
  }

  /**
   * Get a single report by ID
   */
  @Get('/:id')
  @Use(authenticate)
  async getReportById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Report ID is required',
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

      const report = await this.reportService.getReportById(id, userId);

      const response: ApiResponse = {
        success: true,
        data: report,
        message: 'Security report retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 404;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Report not found',
          statusCode
        }
      });
    }
  }

  /**
   * Update report status
   */
  @Put('/:id/status')
  @Use(authenticate)
  @Validate([
    body('status').isIn(['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']).withMessage('Invalid status')
  ])
  async updateReportStatus(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Report ID is required',
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

      const report = await this.reportService.updateReportStatus(id, userId, status);

      const response: ApiResponse = {
        success: true,
        data: report,
        message: 'Report status updated successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to update report status',
          statusCode
        }
      });
    }
  }

  /**
   * Delete a report
   */
  @Delete('/:id')
  @Use(authenticate)
  async deleteReport(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Report ID is required',
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

      await this.reportService.deleteReport(id, userId);

      const response: ApiResponse = {
        success: true,
        data: null,
        message: 'Report deleted successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to delete report',
          statusCode
        }
      });
    }
  }
}
