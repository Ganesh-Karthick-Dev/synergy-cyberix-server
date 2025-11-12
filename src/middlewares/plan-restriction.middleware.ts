import { Request, Response, NextFunction } from 'express';
import { PlanRestrictionService } from '../modules/services/plan-restriction.service';

const planRestrictionService = new PlanRestrictionService();

/**
 * Middleware to check if user can create a project
 */
export const checkProjectLimit = async (req: Request, res: Response, next: NextFunction) => {
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

    const canCreate = await planRestrictionService.canCreateProject(userId);

    if (!canCreate.allowed) {
      res.status(403).json({
        success: false,
        error: {
          message: canCreate.reason || 'Project creation limit reached',
          statusCode: 403
        }
      });
      return;
    }

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to verify project limit',
        statusCode: 500
      }
    });
  }
};

/**
 * Middleware to check if user can run a scan on a project
 */
export const checkScanLimit = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.user?.id;
    const projectId = req.body.projectId || req.params.projectId;

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

    const canScan = await planRestrictionService.canRunScan(userId, projectId);

    if (!canScan.allowed) {
      res.status(403).json({
        success: false,
        error: {
          message: canScan.reason || 'Scan limit reached for this project',
          statusCode: 403
        }
      });
      return;
    }

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to verify scan limit',
        statusCode: 500
      }
    });
  }
};
