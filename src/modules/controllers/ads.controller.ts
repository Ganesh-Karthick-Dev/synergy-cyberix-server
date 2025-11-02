import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';
import { AdsService } from '../services';

@Service()
@Controller('/api/ads')
export class AdsController {
  private adsService: AdsService;

  constructor() {
    this.adsService = new AdsService();
  }
  @Get('/')
  async getAllAds(req: Request, res: Response): Promise<void> {
    try {
      const { search, status, priority } = req.query;
      
      const ads = await this.adsService.getAllAds({
        search: search as string | undefined,
        status: status as string | undefined,
        priority: priority as string | undefined,
      });

      const response: ApiResponse = {
        success: true,
        data: ads,
        message: 'Ads retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve ads',
          statusCode
        }
      });
    }
  }

  @Get('/stats')
  async getAdStats(req: Request, res: Response): Promise<void> {
    try {
      const stats = await this.adsService.getAdStats();

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Ad stats retrieved successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve ad stats',
          statusCode
        }
      });
    }
  }

  @Post('/')
  @Validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('content').notEmpty().withMessage('Content is required'),
    body('priority').isIn(['high', 'medium', 'low']).withMessage('Invalid priority'),
    body('startDate').isISO8601().withMessage('Invalid start date'),
    body('endDate').isISO8601().withMessage('Invalid end date')
  ])
  async createAd(req: Request, res: Response): Promise<void> {
    try {
      const { title, content, link, priority, startDate, endDate, isActive } = req.body;

      const newAd = await this.adsService.createAd({
        title,
        content,
        link,
        priority,
        startDate,
        endDate,
        isActive,
      });

      const response: ApiResponse = {
        success: true,
        data: newAd,
        message: 'Ad created successfully'
      };

      res.status(201).json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to create ad',
          statusCode
        }
      });
    }
  }

  @Put('/deactivate-all')
  async deactivateAllAds(req: Request, res: Response): Promise<void> {
    try {
      const result = await this.adsService.deactivateAllAds();

      const response: ApiResponse = {
        success: true,
        data: result,
        message: result.message,
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to deactivate all ads',
          statusCode
        }
      });
    }
  }

  @Put('/:id/toggle')
  async toggleAd(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Ad ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const updatedAd = await this.adsService.toggleAdStatus(id);

      const response: ApiResponse = {
        success: true,
        data: updatedAd,
        message: `Ad ${updatedAd.isActive ? 'activated' : 'deactivated'} successfully`
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to toggle ad',
          statusCode
        }
      });
    }
  }

  @Put('/:id')
  async updateAd(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData = req.body;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Ad ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const updatedAd = await this.adsService.updateAd(id, updateData);

      const response: ApiResponse = {
        success: true,
        data: updatedAd,
        message: 'Ad updated successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to update ad',
          statusCode
        }
      });
    }
  }

  @Delete('/:id')
  async deleteAd(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Ad ID is required',
            statusCode: 400
          }
        });
        return;
      }

      const result = await this.adsService.deleteAd(id);

      const response: ApiResponse = {
        success: true,
        data: result,
        message: 'Ad deleted successfully'
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to delete ad',
          statusCode
        }
      });
    }
  }
}
