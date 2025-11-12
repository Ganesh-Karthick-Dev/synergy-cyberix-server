import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import { PlanRestrictionService } from './plan-restriction.service';

@Service()
export class SecurityReportService {
  private planRestrictionService: PlanRestrictionService;

  constructor() {
    this.planRestrictionService = new PlanRestrictionService();
  }

  /**
   * Create a security report (scan result) with project linking and restriction checking
   */
  async createReport(userId: string, data: {
    projectId?: string;
    toolId: string;
    title: string;
    content: string;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    status?: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED';
    metadata?: Record<string, any>;
  }) {
    try {
      // If projectId is provided, check scan limit
      if (data.projectId) {
        const canScan = await this.planRestrictionService.canRunScan(userId, data.projectId);
        
        if (!canScan.allowed) {
          throw new CustomError(canScan.reason || 'Scan limit reached for this project', 403);
        }

        // Verify project belongs to user
        const project = await prisma.project.findFirst({
          where: {
            id: data.projectId,
            userId,
            status: 'ACTIVE'
          }
        });

        if (!project) {
          throw new CustomError('Project not found or you do not have access to it', 404);
        }
      }

      const report = await prisma.securityReport.create({
        data: {
          userId,
          projectId: data.projectId,
          toolId: data.toolId,
          title: data.title,
          content: data.content,
          severity: data.severity || 'MEDIUM',
          status: data.status || 'OPEN',
          metadata: data.metadata || {}
        },
        include: {
          project: {
            select: {
              id: true,
              name: true,
              target: true
            }
          },
          tool: {
            select: {
              id: true,
              name: true,
              category: true
            }
          },
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true
            }
          }
        }
      });

      logger.info(`Security report created: ${report.id} by user ${userId} for project ${data.projectId || 'none'}`);
      return report;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error creating security report:', error);
      throw new CustomError('Failed to create security report', 500);
    }
  }

  /**
   * Get reports for a user
   */
  async getUserReports(userId: string, filters?: {
    projectId?: string;
    toolId?: string;
    status?: string;
    severity?: string;
  }) {
    try {
      const where: any = { userId };

      if (filters?.projectId) {
        where.projectId = filters.projectId;
      }

      if (filters?.toolId) {
        where.toolId = filters.toolId;
      }

      if (filters?.status) {
        where.status = filters.status;
      }

      if (filters?.severity) {
        where.severity = filters.severity;
      }

      const reports = await prisma.securityReport.findMany({
        where,
        include: {
          project: {
            select: {
              id: true,
              name: true,
              target: true
            }
          },
          tool: {
            select: {
              id: true,
              name: true,
              category: true
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      });

      return reports;
    } catch (error) {
      logger.error('Error fetching user reports:', error);
      throw new CustomError('Failed to retrieve security reports', 500);
    }
  }

  /**
   * Get reports for a specific project
   */
  async getProjectReports(projectId: string, userId: string) {
    try {
      // Verify project belongs to user
      const project = await prisma.project.findFirst({
        where: {
          id: projectId,
          userId
        }
      });

      if (!project) {
        throw new CustomError('Project not found', 404);
      }

      const reports = await prisma.securityReport.findMany({
        where: {
          projectId,
          userId
        },
        include: {
          tool: {
            select: {
              id: true,
              name: true,
              category: true
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      });

      return reports;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching project reports:', error);
      throw new CustomError('Failed to retrieve project reports', 500);
    }
  }

  /**
   * Get a single report by ID
   */
  async getReportById(reportId: string, userId: string) {
    try {
      const report = await prisma.securityReport.findFirst({
        where: {
          id: reportId,
          userId
        },
        include: {
          project: {
            select: {
              id: true,
              name: true,
              target: true,
              description: true
            }
          },
          tool: {
            select: {
              id: true,
              name: true,
              category: true,
              description: true
            }
          },
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true
            }
          }
        }
      });

      if (!report) {
        throw new CustomError('Report not found', 404);
      }

      return report;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching report:', error);
      throw new CustomError('Failed to retrieve report', 500);
    }
  }

  /**
   * Update report status
   */
  async updateReportStatus(reportId: string, userId: string, status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED') {
    try {
      const report = await prisma.securityReport.findFirst({
        where: {
          id: reportId,
          userId
        }
      });

      if (!report) {
        throw new CustomError('Report not found', 404);
      }

      const updatedReport = await prisma.securityReport.update({
        where: { id: reportId },
        data: { status },
        include: {
          project: {
            select: {
              id: true,
              name: true
            }
          },
          tool: {
            select: {
              id: true,
              name: true
            }
          }
        }
      });

      logger.info(`Report status updated: ${reportId} to ${status} by user ${userId}`);
      return updatedReport;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error updating report status:', error);
      throw new CustomError('Failed to update report status', 500);
    }
  }

  /**
   * Delete a report
   */
  async deleteReport(reportId: string, userId: string) {
    try {
      const report = await prisma.securityReport.findFirst({
        where: {
          id: reportId,
          userId
        }
      });

      if (!report) {
        throw new CustomError('Report not found', 404);
      }

      await prisma.securityReport.delete({
        where: { id: reportId }
      });

      logger.info(`Report deleted: ${reportId} by user ${userId}`);
      return { success: true };
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error deleting report:', error);
      throw new CustomError('Failed to delete report', 500);
    }
  }
}
