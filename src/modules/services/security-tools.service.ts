import { prisma } from '../../config/db';
import { SecurityCategory } from '@prisma/client';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';

export interface SecurityToolData {
  id: string;
  name: string;
  description: string | null;
  category: SecurityCategory;
  isActive: boolean;
  config: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolStatusResponse {
  id: string;
  name: string;
  isActive: boolean;
  status: 'active' | 'maintenance';
  message?: string;
}

@Service()
export class SecurityToolsService {
  async getAllTools(filters?: {
    category?: SecurityCategory;
    search?: string;
    status?: 'active' | 'inactive';
  }): Promise<SecurityToolData[]> {
    const { category, search, status } = filters || {};

    const where: any = {};

    if (category) {
      where.category = category;
    }

    if (status) {
      where.isActive = status === 'active';
    }

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' as const } },
        { description: { contains: search, mode: 'insensitive' as const } }
      ];
    }

    const tools = await prisma.securityTool.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    return tools;
  }

  async getToolById(id: string): Promise<SecurityToolData | null> {
    const tool = await prisma.securityTool.findUnique({
      where: { id }
    });

    return tool;
  }

  async toggleTool(id: string, isActive: boolean): Promise<SecurityToolData> {
    const tool = await prisma.securityTool.findUnique({
      where: { id }
    });

    if (!tool) {
      throw new CustomError('Security tool not found', 404);
    }

    const updatedTool = await prisma.securityTool.update({
      where: { id },
      data: { isActive }
    });

    logger.info(`Security tool ${isActive ? 'enabled' : 'disabled'}`, {
      toolId: id,
      toolName: tool.name,
      isActive
    });

    return updatedTool;
  }

  async getToolCategories(): Promise<any[]> {
    // Get categories and count of tools in each
    const categories = await prisma.securityTool.groupBy({
      by: ['category'],
      _count: {
        id: true
      },
      where: {
        isActive: true
      }
    });

    const categoryDetails = {
      [SecurityCategory.VULNERABILITY_SCANNER]: {
        name: 'Vulnerability Scanner',
        description: 'Automated vulnerability scanning tools'
      },
      [SecurityCategory.PENETRATION_TESTING]: {
        name: 'Penetration Testing',
        description: 'Advanced penetration testing suites'
      },
      [SecurityCategory.COMPLIANCE_CHECKER]: {
        name: 'Compliance Checker',
        description: 'Automated compliance checking for various standards'
      },
      [SecurityCategory.THREAT_DETECTION]: {
        name: 'Threat Detection',
        description: 'Real-time threat detection and monitoring'
      },
      [SecurityCategory.ACCESS_CONTROL]: {
        name: 'Access Control',
        description: 'Authentication and authorization tools'
      },
      [SecurityCategory.ENCRYPTION]: {
        name: 'Encryption',
        description: 'Data encryption and security tools'
      },
      [SecurityCategory.MONITORING]: {
        name: 'Monitoring',
        description: 'System monitoring and alerting tools'
      },
      [SecurityCategory.CLOUD_SECURITY]: {
        name: 'Cloud Security',
        description: 'Cloud platform security and protection tools'
      },
      [SecurityCategory.OVERVIEW_SCAN]: {
        name: 'Overview Scan',
        description: 'Comprehensive security overview and assessment'
      }
    };

    return categories.map(cat => ({
      id: cat.category,
      name: categoryDetails[cat.category]?.name || cat.category,
      description: categoryDetails[cat.category]?.description || '',
      toolCount: cat._count.id
    }));
  }

  async getToolsStatus(): Promise<ToolStatusResponse[]> {
    const tools = await prisma.securityTool.findMany({
      select: {
        id: true,
        name: true,
        isActive: true
      }
    });

    return tools.map(tool => ({
      id: tool.id,
      name: tool.name,
      isActive: tool.isActive,
      status: tool.isActive ? 'active' : 'maintenance',
      message: tool.isActive ? undefined : 'This tool is currently under maintenance'
    }));
  }

  async createTool(toolData: {
    name: string;
    description?: string;
    category: SecurityCategory;
    config?: any;
  }): Promise<SecurityToolData> {
    const tool = await prisma.securityTool.create({
      data: toolData
    });

    logger.info('Security tool created', { toolId: tool.id, toolName: tool.name });

    return tool;
  }

  async updateTool(id: string, updateData: Partial<{
    name: string;
    description: string;
    category: SecurityCategory;
    isActive: boolean;
    config: any;
  }>): Promise<SecurityToolData> {
    const tool = await prisma.securityTool.findUnique({
      where: { id }
    });

    if (!tool) {
      throw new CustomError('Security tool not found', 404);
    }

    const updatedTool = await prisma.securityTool.update({
      where: { id },
      data: updateData
    });

    logger.info('Security tool updated', { toolId: id, toolName: tool.name });

    return updatedTool;
  }

  async deleteTool(id: string): Promise<void> {
    const tool = await prisma.securityTool.findUnique({
      where: { id }
    });

    if (!tool) {
      throw new CustomError('Security tool not found', 404);
    }

    await prisma.securityTool.delete({
      where: { id }
    });

    logger.info('Security tool deleted', { toolId: id, toolName: tool.name });
  }

  async getEnabledTools(): Promise<SecurityToolData[]> {
    const enabledTools = await prisma.securityTool.findMany({
      where: {
        isActive: true
      },
      orderBy: { createdAt: 'asc' }
    });

    return enabledTools;
  }

  async deployUpdates(): Promise<void> {
    // This could trigger deployment of tool updates
    // For now, just log the deployment
    logger.info('Security tools updates deployed');

    // You could add logic here to:
    // - Update tool configurations
    // - Restart services
    // - Send notifications
    // - Update cache/CDN
  }
}
