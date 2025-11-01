import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import { Prisma } from '@prisma/client';

@Service()
export class AdsService {
  /**
   * Get all post ads with optional filters
   */
  async getAllAds(filters?: {
    search?: string;
    status?: string;
    priority?: string;
  }) {
    try {
      const where: Prisma.PostAdWhereInput = {};

      // Search filter
      if (filters?.search) {
        const searchTerm = filters.search.toLowerCase();
        where.OR = [
          { title: { contains: searchTerm, mode: 'insensitive' } },
          { content: { contains: searchTerm, mode: 'insensitive' } },
        ];
      }

      // Status filter
      if (filters?.status) {
        where.isActive = filters.status === 'active';
      }

      // Priority filter
      if (filters?.priority) {
        where.priority = filters.priority.toUpperCase() as any;
      }

      const ads = await prisma.postAd.findMany({
        where,
        orderBy: [
          { priority: 'desc' },
          { createdAt: 'desc' },
        ],
      });

      // Transform database format to API format
      return ads.map(this.transformAd);
    } catch (error: any) {
      logger.error('Error fetching ads:', error);
      throw new CustomError('Failed to fetch ads', 500);
    }
  }

  /**
   * Get ad by ID
   */
  async getAdById(id: string) {
    try {
      const ad = await prisma.postAd.findUnique({
        where: { id },
      });

      if (!ad) {
        throw new CustomError('Ad not found', 404);
      }

      return this.transformAd(ad);
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching ad:', error);
      throw new CustomError('Failed to fetch ad', 500);
    }
  }

  /**
   * Get ad statistics
   */
  async getAdStats() {
    try {
      const [totalAds, activeAds, allAds] = await Promise.all([
        prisma.postAd.count(),
        prisma.postAd.count({ where: { isActive: true } }),
        prisma.postAd.findMany({
          select: {
            clicks: true,
            impressions: true,
          },
        }),
      ]);

      const totalClicks = allAds.reduce((sum, ad) => sum + ad.clicks, 0);
      const totalImpressions = allAds.reduce((sum, ad) => sum + ad.impressions, 0);
      const clickThroughRate = totalImpressions > 0 
        ? ((totalClicks / totalImpressions) * 100).toFixed(2)
        : '0.00';

      // Get top performing ad
      const topAd = await prisma.postAd.findFirst({
        orderBy: [
          { clicks: 'desc' },
        ],
        select: {
          title: true,
        },
      });

      return {
        totalAds,
        activeAds,
        totalClicks,
        totalImpressions,
        clickThroughRate: parseFloat(clickThroughRate),
        topPerformingAd: topAd?.title || 'N/A',
      };
    } catch (error: any) {
      logger.error('Error fetching ad stats:', error);
      throw new CustomError('Failed to fetch ad statistics', 500);
    }
  }

  /**
   * Create a new post ad
   */
  async createAd(data: {
    title: string;
    content: string;
    link?: string;
    priority: 'high' | 'medium' | 'low';
    startDate: string;
    endDate: string;
    isActive?: boolean;
  }) {
    try {
      const priorityMap: Record<string, any> = {
        high: 'HIGH',
        medium: 'MEDIUM',
        low: 'LOW',
      };

      const ad = await prisma.postAd.create({
        data: {
          title: data.title,
          content: data.content,
          link: data.link || null,
          priority: priorityMap[data.priority] || 'MEDIUM',
          startDate: new Date(data.startDate),
          endDate: new Date(data.endDate),
          isActive: data.isActive ?? false,
          clicks: 0,
          impressions: 0,
        },
      });

      return this.transformAd(ad);
    } catch (error: any) {
      logger.error('Error creating ad:', error);
      throw new CustomError('Failed to create ad', 500);
    }
  }

  /**
   * Update an existing post ad
   */
  async updateAd(id: string, data: {
    title?: string;
    content?: string;
    link?: string;
    priority?: 'high' | 'medium' | 'low';
    startDate?: string;
    endDate?: string;
    isActive?: boolean;
  }) {
    try {
      // Check if ad exists
      const existingAd = await prisma.postAd.findUnique({
        where: { id },
      });

      if (!existingAd) {
        throw new CustomError('Ad not found', 404);
      }

      const updateData: any = {};

      if (data.title !== undefined) updateData.title = data.title;
      if (data.content !== undefined) updateData.content = data.content;
      if (data.link !== undefined) updateData.link = data.link || null;
      if (data.priority !== undefined) {
        const priorityMap: Record<string, any> = {
          high: 'HIGH',
          medium: 'MEDIUM',
          low: 'LOW',
        };
        updateData.priority = priorityMap[data.priority] || 'MEDIUM';
      }
      if (data.startDate !== undefined) updateData.startDate = new Date(data.startDate);
      if (data.endDate !== undefined) updateData.endDate = new Date(data.endDate);
      if (data.isActive !== undefined) updateData.isActive = data.isActive;

      const ad = await prisma.postAd.update({
        where: { id },
        data: updateData,
      });

      return this.transformAd(ad);
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error updating ad:', error);
      throw new CustomError('Failed to update ad', 500);
    }
  }

  /**
   * Toggle ad active status
   */
  async toggleAdStatus(id: string) {
    try {
      const ad = await prisma.postAd.findUnique({
        where: { id },
      });

      if (!ad) {
        throw new CustomError('Ad not found', 404);
      }

      // If activating, deactivate all other ads first
      if (!ad.isActive) {
        await prisma.postAd.updateMany({
          where: { isActive: true },
          data: { isActive: false },
        });
      }

      const updatedAd = await prisma.postAd.update({
        where: { id },
        data: { isActive: !ad.isActive },
      });

      return this.transformAd(updatedAd);
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error toggling ad status:', error);
      throw new CustomError('Failed to toggle ad status', 500);
    }
  }

  /**
   * Deactivate all ads
   */
  async deactivateAllAds() {
    try {
      const result = await prisma.postAd.updateMany({
        where: { isActive: true },
        data: { isActive: false },
      });

      return {
        count: result.count,
        message: `${result.count} ad(s) deactivated successfully`,
      };
    } catch (error: any) {
      logger.error('Error deactivating all ads:', error);
      throw new CustomError('Failed to deactivate all ads', 500);
    }
  }

  /**
   * Delete a post ad
   */
  async deleteAd(id: string) {
    try {
      const ad = await prisma.postAd.findUnique({
        where: { id },
      });

      if (!ad) {
        throw new CustomError('Ad not found', 404);
      }

      await prisma.postAd.delete({
        where: { id },
      });

      return { message: 'Ad deleted successfully' };
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error deleting ad:', error);
      throw new CustomError('Failed to delete ad', 500);
    }
  }

  /**
   * Transform database ad to API format
   */
  private transformAd(ad: any) {
    const priorityMap: Record<string, string> = {
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
    };

    return {
      id: ad.id,
      title: ad.title,
      content: ad.content,
      link: ad.link || undefined,
      isActive: ad.isActive,
      priority: priorityMap[ad.priority] || 'medium',
      startDate: ad.startDate ? new Date(ad.startDate).toISOString().split('T')[0] : '',
      endDate: ad.endDate ? new Date(ad.endDate).toISOString().split('T')[0] : '',
      createdAt: ad.createdAt ? new Date(ad.createdAt).toISOString().split('T')[0] : '',
      updatedAt: ad.updatedAt ? new Date(ad.updatedAt).toISOString().split('T')[0] : '',
      clicks: ad.clicks || 0,
      impressions: ad.impressions || 0,
    };
  }
}

