import { prisma } from '../../config/db';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import { PlanRestrictionService } from './plan-restriction.service';

@Service()
export class ProjectService {
  private planRestrictionService: PlanRestrictionService;

  constructor() {
    this.planRestrictionService = new PlanRestrictionService();
  }

  /**
   * Create a new project for user
   */
  async createProject(userId: string, data: {
    name: string;
    description?: string;
    target?: string;
  }) {
    try {
      // Check if user can create project
      const canCreate = await this.planRestrictionService.canCreateProject(userId);
      if (!canCreate.allowed) {
        throw new CustomError(canCreate.reason || 'Cannot create project', 403);
      }

      const project = await prisma.project.create({
        data: {
          userId,
          name: data.name,
          description: data.description,
          target: data.target,
          status: 'ACTIVE'
        },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true
            }
          },
          scans: {
            take: 5,
            orderBy: { createdAt: 'desc' },
            select: {
              id: true,
              title: true,
              severity: true,
              status: true,
              createdAt: true
            }
          }
        }
      });

      logger.info(`Project created: ${project.id} by user ${userId}`);
      return project;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error creating project:', error);
      throw new CustomError('Failed to create project', 500);
    }
  }

  /**
   * Get all projects for a user
   */
  async getUserProjects(userId: string, includeArchived: boolean = false) {
    try {
      const where: any = {
        userId
      };

      if (!includeArchived) {
        where.status = 'ACTIVE';
      }

      const projects = await prisma.project.findMany({
        where,
        include: {
          scans: {
            take: 5,
            orderBy: { createdAt: 'desc' },
            select: {
              id: true,
              title: true,
              severity: true,
              status: true,
              createdAt: true
            }
          },
          _count: {
            select: {
              scans: true
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      });

      return projects;
    } catch (error) {
      logger.error('Error fetching user projects:', error);
      throw new CustomError('Failed to retrieve projects', 500);
    }
  }

  /**
   * Get a single project by ID
   */
  async getProjectById(projectId: string, userId: string) {
    try {
      const project = await prisma.project.findFirst({
        where: {
          id: projectId,
          userId
        },
        include: {
          scans: {
            orderBy: { createdAt: 'desc' },
            include: {
              tool: {
                select: {
                  id: true,
                  name: true,
                  category: true
                }
              }
            }
          },
          _count: {
            select: {
              scans: true
            }
          }
        }
      });

      if (!project) {
        throw new CustomError('Project not found', 404);
      }

      return project;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching project:', error);
      throw new CustomError('Failed to retrieve project', 500);
    }
  }

  /**
   * Update a project
   */
  async updateProject(projectId: string, userId: string, data: {
    name?: string;
    description?: string;
    target?: string;
    status?: 'ACTIVE' | 'ARCHIVED' | 'DELETED';
  }) {
    try {
      // Verify project belongs to user
      const existingProject = await prisma.project.findFirst({
        where: {
          id: projectId,
          userId
        }
      });

      if (!existingProject) {
        throw new CustomError('Project not found', 404);
      }

      const project = await prisma.project.update({
        where: { id: projectId },
        data: {
          ...(data.name && { name: data.name }),
          ...(data.description !== undefined && { description: data.description }),
          ...(data.target !== undefined && { target: data.target }),
          ...(data.status && { status: data.status })
        },
        include: {
          scans: {
            take: 5,
            orderBy: { createdAt: 'desc' }
          }
        }
      });

      logger.info(`Project updated: ${projectId} by user ${userId}`);
      return project;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error updating project:', error);
      throw new CustomError('Failed to update project', 500);
    }
  }

  /**
   * Delete a project (soft delete by setting status to DELETED)
   */
  async deleteProject(projectId: string, userId: string) {
    try {
      // Verify project belongs to user
      const existingProject = await prisma.project.findFirst({
        where: {
          id: projectId,
          userId
        }
      });

      if (!existingProject) {
        throw new CustomError('Project not found', 404);
      }

      // Soft delete by setting status to DELETED
      const project = await prisma.project.update({
        where: { id: projectId },
        data: {
          status: 'DELETED'
        }
      });

      logger.info(`Project deleted: ${projectId} by user ${userId}`);
      return project;
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error deleting project:', error);
      throw new CustomError('Failed to delete project', 500);
    }
  }

  /**
   * Get project statistics
   */
  async getProjectStats(projectId: string, userId: string) {
    try {
      const project = await this.getProjectById(projectId, userId);
      const limits = await this.planRestrictionService.getUserPlanLimits(userId);
      const scanCount = await this.planRestrictionService.getProjectScanCount(projectId, userId);

      return {
        project: {
          id: project.id,
          name: project.name,
          description: project.description,
          target: project.target,
          status: project.status,
          createdAt: project.createdAt
        },
        scans: {
          count: scanCount,
          limit: limits.maxScansPerProject === -1 ? 'Unlimited' : limits.maxScansPerProject,
          remaining: limits.maxScansPerProject === -1 ? 'Unlimited' : Math.max(0, limits.maxScansPerProject - scanCount)
        }
      };
    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      logger.error('Error fetching project stats:', error);
      throw new CustomError('Failed to retrieve project statistics', 500);
    }
  }
}
