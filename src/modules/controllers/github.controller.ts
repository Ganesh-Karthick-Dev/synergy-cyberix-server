import { Request, Response } from 'express';
import { Controller, Get, Post } from '../../decorators/controller.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { authenticate } from '../../middlewares/auth.middleware';
import { Use } from '../../decorators/middleware.decorator';
import { GitHubService } from '../services/github.service';
import passport from 'passport';
import { config } from '../../config/env.config';

@Service()
@Controller('/api/github')
export class GitHubController {
  private githubService: GitHubService;

  constructor() {
    this.githubService = new GitHubService();
  }

  /**
   * Initiate GitHub OAuth flow
   * GET /api/github/auth
   */
  @Get('/auth')
  async initiateAuth(req: Request, res: Response): Promise<void> {
    try {
      // Store redirect URL if provided (for Electron app)
      if (req.query.redirect) {
        (req.session as any).githubRedirect = req.query.redirect as string;
      }

      // Initiate OAuth flow
      passport.authenticate('github', {
        scope: ['user:email', 'read:org', 'repo'],
        session: false,
      })(req, res);
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: {
          message: error.message || 'Failed to initiate GitHub authentication',
          statusCode: 500,
        },
      });
    }
  }

  /**
   * GitHub OAuth callback
   * GET /api/github/callback
   */
  @Get('/callback')
  async handleCallback(req: Request, res: Response): Promise<void> {
    passport.authenticate('github', { session: false }, async (err: any, user: any, info: any) => {
      try {
        if (err || !user) {
          return res.status(401).json({
            success: false,
            error: {
              message: err?.message || info?.message || 'GitHub authentication failed',
              statusCode: 401,
            },
          });
        }

        // Get access token from the OAuth flow
        // Note: In a real implementation, you'd store this token securely
        const accessToken = (user as any).accessToken;

        if (!accessToken) {
          return res.status(401).json({
            success: false,
            error: {
              message: 'Access token not received',
              statusCode: 401,
            },
          });
        }

        // Get user info from GitHub
        const githubUser = await this.githubService.getUserInfo(accessToken);

        // Check if redirect URL is stored (for Electron app)
        const redirectUrl = (req.session as any)?.githubRedirect;

        if (redirectUrl) {
          // Redirect to Electron app with token
          delete (req.session as any).githubRedirect;
          return res.redirect(
            `${redirectUrl}?token=${accessToken}&user=${encodeURIComponent(JSON.stringify(githubUser))}`
          );
        }

        // Return token and user info for API usage
        const response: ApiResponse = {
          success: true,
          data: {
            accessToken,
            user: githubUser,
          },
          message: 'GitHub authentication successful',
        };

        res.json(response);
      } catch (error: any) {
        res.status(500).json({
          success: false,
          error: {
            message: error.message || 'Failed to process GitHub callback',
            statusCode: 500,
          },
        });
      }
    })(req, res);
  }

  /**
   * Get user's organizations
   * GET /api/github/organizations
   * Requires: Authorization header with Bearer token (GitHub access token)
   */
  @Get('/organizations')
  @Use(authenticate)
  async getOrganizations(req: Request, res: Response): Promise<void> {
    try {
      // Get GitHub access token from request
      // In Electron app, this would be passed as a header or query param
      const githubToken = req.headers['x-github-token'] as string || 
                         req.query.token as string ||
                         req.headers.authorization?.replace('Bearer ', '');

      if (!githubToken) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
      }

      const organizations = await this.githubService.getOrganizations(githubToken);

      const response: ApiResponse = {
        success: true,
        data: organizations,
        message: 'Organizations retrieved successfully',
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve organizations',
          statusCode,
        },
      });
    }
  }

  /**
   * Get repositories for an organization
   * GET /api/github/repos/:org
   * Requires: Authorization header with Bearer token (GitHub access token)
   */
  @Get('/repos/:org')
  @Use(authenticate)
  async getRepositories(req: Request, res: Response): Promise<void> {
    try {
      const { org } = req.params;
      const githubToken = req.headers['x-github-token'] as string || 
                         req.query.token as string ||
                         req.headers.authorization?.replace('Bearer ', '');

      if (!githubToken) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
      }

      const repositories = await this.githubService.getOrganizationRepos(githubToken, org);

      const response: ApiResponse = {
        success: true,
        data: repositories,
        message: 'Repositories retrieved successfully',
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve repositories',
          statusCode,
        },
      });
    }
  }

  /**
   * Get repository contents (all code)
   * GET /api/github/repo/:owner/:repo/contents
   * Query params: path (optional), branch (optional)
   * Requires: Authorization header with Bearer token (GitHub access token)
   */
  @Get('/repo/:owner/:repo/contents')
  @Use(authenticate)
  async getRepositoryContents(req: Request, res: Response): Promise<void> {
    try {
      const { owner, repo } = req.params;
      const path = (req.query.path as string) || '';
      const branch = req.query.branch as string | undefined;
      const githubToken = req.headers['x-github-token'] as string || 
                         req.query.token as string ||
                         req.headers.authorization?.replace('Bearer ', '');

      if (!githubToken) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
      }

      const contents = await this.githubService.getRepositoryContents(
        githubToken,
        owner,
        repo,
        path,
        branch
      );

      const response: ApiResponse = {
        success: true,
        data: contents,
        message: 'Repository contents retrieved successfully',
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve repository contents',
          statusCode,
        },
      });
    }
  }

  /**
   * Get repository branches
   * GET /api/github/repo/:owner/:repo/branches
   * Requires: Authorization header with Bearer token (GitHub access token)
   */
  @Get('/repo/:owner/:repo/branches')
  @Use(authenticate)
  async getBranches(req: Request, res: Response): Promise<void> {
    try {
      const { owner, repo } = req.params;
      const githubToken = req.headers['x-github-token'] as string || 
                         req.query.token as string ||
                         req.headers.authorization?.replace('Bearer ', '');

      if (!githubToken) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
      }

      const branches = await this.githubService.getRepositoryBranches(githubToken, owner, repo);

      const response: ApiResponse = {
        success: true,
        data: branches,
        message: 'Branches retrieved successfully',
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve branches',
          statusCode,
        },
      });
    }
  }

  /**
   * Get user info
   * GET /api/github/user
   * Requires: Authorization header with Bearer token (GitHub access token)
   */
  @Get('/user')
  @Use(authenticate)
  async getUserInfo(req: Request, res: Response): Promise<void> {
    try {
      const githubToken = req.headers['x-github-token'] as string || 
                         req.query.token as string ||
                         req.headers.authorization?.replace('Bearer ', '');

      if (!githubToken) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
      }

      const userInfo = await this.githubService.getUserInfo(githubToken);

      const response: ApiResponse = {
        success: true,
        data: userInfo,
        message: 'User info retrieved successfully',
      };

      res.json(response);
    } catch (error: any) {
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        error: {
          message: error.message || 'Failed to retrieve user info',
          statusCode,
        },
      });
    }
  }
}

