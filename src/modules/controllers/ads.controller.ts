import { Request, Response } from 'express';
import { Controller, Get, Post, Put, Delete } from '../../decorators/controller.decorator';
import { Validate } from '../../decorators/validation.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { body } from 'express-validator';

@Service()
@Controller('/api/ads')
export class AdsController {
  @Get('/')
  async getAllAds(req: Request, res: Response): Promise<void> {
    try {
      const { search, status, priority } = req.query;
      
      // Mock data based on post-ads/page.tsx structure
      const ads = [
        {
          id: '1',
          title: '50% OFF - Professional Security Scanner',
          content: 'Limited time offer! Get 50% discount on our Professional Security Scanner plan. Secure your website today!',
          link: 'https://cyberix.com/purchase?discount=50off',
          isActive: true,
          priority: 'high',
          startDate: '2024-01-15',
          endDate: '2024-02-15',
          createdAt: '2024-01-10',
          updatedAt: '2024-01-12',
          clicks: 1247,
          impressions: 15680
        },
        {
          id: '2',
          title: '30% OFF - Enterprise Security Suite',
          content: 'Special discount! Save 30% on our Enterprise Security Suite. Perfect for large organizations!',
          link: 'https://cyberix.com/purchase?discount=30off',
          isActive: false,
          priority: 'medium',
          startDate: '2024-01-20',
          endDate: '2024-03-20',
          createdAt: '2024-01-18',
          updatedAt: '2024-01-19',
          clicks: 892,
          impressions: 12340
        },
        {
          id: '3',
          title: 'Buy 2 Get 1 FREE - Basic Plans',
          content: 'Amazing deal! Purchase 2 Basic Security Scanner licenses and get 1 absolutely free!',
          link: 'https://cyberix.com/purchase?deal=buy2get1',
          isActive: false,
          priority: 'low',
          startDate: '2024-01-25',
          endDate: '2024-02-25',
          createdAt: '2024-01-22',
          updatedAt: '2024-01-23',
          clicks: 456,
          impressions: 7890
        }
      ];

      // Apply filters
      let filteredAds = ads;
      
      if (search) {
        const searchTerm = (search as string).toLowerCase();
        filteredAds = filteredAds.filter(ad => 
          ad.title.toLowerCase().includes(searchTerm) ||
          ad.content.toLowerCase().includes(searchTerm)
        );
      }
      
      if (status) {
        filteredAds = filteredAds.filter(ad => ad.isActive === (status === 'active'));
      }
      
      if (priority) {
        filteredAds = filteredAds.filter(ad => ad.priority === priority);
      }

      const response: ApiResponse = {
        success: true,
        data: filteredAds,
        message: 'Ads retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve ads',
          statusCode: 500
        }
      });
    }
  }

  @Get('/stats')
  async getAdStats(req: Request, res: Response): Promise<void> {
    try {
      const stats = {
        totalAds: 3,
        activeAds: 1,
        totalClicks: 2595,
        totalImpressions: 35910
      };

      const response: ApiResponse = {
        success: true,
        data: stats,
        message: 'Ad stats retrieved successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to retrieve ad stats',
          statusCode: 500
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
      const { title, content, link, priority, startDate, endDate } = req.body;

      const newAd = {
        id: Date.now().toString(),
        title,
        content,
        link: link || null,
        isActive: true,
        priority,
        startDate,
        endDate,
        createdAt: new Date().toISOString().split('T')[0],
        updatedAt: new Date().toISOString().split('T')[0],
        clicks: 0,
        impressions: 0
      };

      const response: ApiResponse = {
        success: true,
        data: newAd,
        message: 'Ad created successfully'
      };

      res.status(201).json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to create ad',
          statusCode: 500
        }
      });
    }
  }

  @Put('/:id')
  async updateAd(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData = req.body;

      // Mock update - in real app, this would update database
      const updatedAd = {
        id,
        ...updateData,
        updatedAt: new Date().toISOString().split('T')[0]
      };

      const response: ApiResponse = {
        success: true,
        data: updatedAd,
        message: 'Ad updated successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to update ad',
          statusCode: 500
        }
      });
    }
  }

  @Put('/:id/toggle')
  async toggleAd(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { isActive } = req.body;

      // Mock toggle - in real app, this would update database
      const response: ApiResponse = {
        success: true,
        data: { id, isActive },
        message: `Ad ${isActive ? 'activated' : 'deactivated'} successfully`
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to toggle ad',
          statusCode: 500
        }
      });
    }
  }

  @Delete('/:id')
  async deleteAd(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // Mock deletion - in real app, this would delete from database
      const response: ApiResponse = {
        success: true,
        message: 'Ad deleted successfully'
      };

      res.json(response);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Failed to delete ad',
          statusCode: 500
        }
      });
    }
  }
}
