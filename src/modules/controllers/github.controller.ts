import { Request, Response } from 'express';
import { Controller, Get, Post } from '../../decorators/controller.decorator';
import { Service } from '../../decorators/service.decorator';
import { ApiResponse } from '../../types';
import { authenticate } from '../../middlewares/auth.middleware';
import { Use } from '../../decorators/middleware.decorator';
import { GitHubService } from '../services/github.service';
import { config } from '../../config/env.config';
import axios from 'axios';
import crypto from 'crypto';

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
   * 
   * Query Parameters:
   * - redirect (optional): Custom redirect URL for Electron app (e.g., myapp://github-callback)
   * 
   * Expected Behavior:
   * 1. Construct GitHub OAuth URL with client_id, redirect_uri, scope, response_type, and state
   * 2. Redirect user to GitHub's OAuth page
   */
  @Get('/auth')
  async initiateAuth(req: Request, res: Response): Promise<void> {
    try {
      // Check if GitHub OAuth is configured
      if (!config.github) {
        res.status(503).json({
          success: false,
          error: {
            message: 'GitHub OAuth is not configured',
            statusCode: 503,
          },
        });
        return;
      }

      // Get redirect URL from query parameter (default for Electron app)
      const redirect = (req.query.redirect as string) || 'myapp://github-callback';

      // Generate state parameter for security
      const state = crypto.randomBytes(32).toString('hex');

      // Store state and redirect URL in session
      if (!req.session) {
        res.status(500).json({
          success: false,
          error: {
            message: 'Session not available',
            statusCode: 500,
          },
        });
        return;
      }

      (req.session as any).githubOAuthState = state;
      (req.session as any).githubRedirect = redirect;

      // Construct GitHub OAuth URL
      const redirectUri = config.github.callbackURL;
      const scope = 'user:email,read:org,repo';
      const githubAuthUrl = `https://github.com/login/oauth/authorize?` +
        `response_type=code&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `scope=${encodeURIComponent(scope)}&` +
        `client_id=${config.github.clientId}&` +
        `state=${state}`;

      // Redirect to GitHub OAuth page
      res.redirect(githubAuthUrl);
    } catch (error: any) {
      console.error('Error initiating GitHub OAuth:', error);
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
   * 
   * Query Parameters (from GitHub):
   * - code: Authorization code from GitHub
   * - state: State parameter (if used)
   * - error: Error code (if authorization failed)
   * - error_description: Error description (if authorization failed)
   * 
   * Expected Behavior:
   * 1. Validate the authorization code and state (if used)
   * 2. Exchange the code for an access token by calling GitHub's token endpoint
   * 3. Get user info from GitHub API using the access token
   * 4. Redirect to the Electron app's custom protocol URL with token and user info
   */
  @Get('/callback')
  async handleCallback(req: Request, res: Response): Promise<void> {
    try {
      // Check if GitHub OAuth is configured
      if (!config.github) {
        const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
        return res.redirect(`${redirectUrl}?error=not_configured&error_description=GitHub OAuth is not configured`);
      }

      const { code, state, error, error_description } = req.query;

      // Handle errors from GitHub
      if (error) {
        const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
        const errorDesc = error_description || error;
        return res.redirect(`${redirectUrl}?error=${error}&error_description=${encodeURIComponent(errorDesc as string)}`);
      }

      // Validate state parameter
      if (state && req.session) {
        const storedState = (req.session as any)?.githubOAuthState;
        if (storedState !== state) {
          const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
          return res.redirect(`${redirectUrl}?error=invalid_state&error_description=State parameter mismatch`);
        }
      }

      // Validate code parameter
      if (!code) {
        const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
        return res.redirect(`${redirectUrl}?error=missing_code&error_description=Authorization code not provided`);
      }

      // Exchange code for access token
      let accessToken: string;
      try {
        const tokenResponse = await axios.post(
          'https://github.com/login/oauth/access_token',
          {
            client_id: config.github.clientId,
            client_secret: config.github.clientSecret,
            code: code,
            redirect_uri: config.github.callbackURL,
          },
          {
            headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json',
            },
          }
        );

        if (tokenResponse.data.error) {
          throw new Error(tokenResponse.data.error_description || tokenResponse.data.error);
        }

        accessToken = tokenResponse.data.access_token;

        if (!accessToken) {
          throw new Error('Access token not received from GitHub');
        }
      } catch (error: any) {
        console.error('Error exchanging code for token:', error);
        const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
        const errorMessage = error.response?.data?.error_description || error.message || 'Failed to exchange code for token';
        return res.redirect(`${redirectUrl}?error=token_exchange_failed&error_description=${encodeURIComponent(errorMessage)}`);
      }

      // Get user info from GitHub API
      let githubUser: any;
      try {
        const userResponse = await axios.get('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json',
          },
        });
        githubUser = userResponse.data;
      } catch (error: any) {
        console.error('Error fetching user info:', error);
        const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
        const errorMessage = error.response?.data?.message || error.message || 'Failed to fetch user info';
        return res.redirect(`${redirectUrl}?error=user_info_failed&error_description=${encodeURIComponent(errorMessage)}`);
      }

      // Get stored redirect URL (for Electron app)
      const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';

      // Clean up session
      if (req.session) {
        delete (req.session as any).githubOAuthState;
        delete (req.session as any).githubRedirect;
      }

      // Redirect to Electron app with token and user info
      const userJson = encodeURIComponent(JSON.stringify(githubUser));
      return res.redirect(`${redirectUrl}?token=${accessToken}&user=${userJson}`);

    } catch (error: any) {
      console.error('OAuth callback error:', error);
      const redirectUrl = (req.session as any)?.githubRedirect || 'myapp://github-callback';
      const errorMessage = error.message || 'Failed to process GitHub callback';
      return res.redirect(`${redirectUrl}?error=callback_failed&error_description=${encodeURIComponent(errorMessage)}`);
    }
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
        res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
        return;
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
        res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
        return;
      }

      if (!org) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Organization name is required',
            statusCode: 400,
          },
        });
        return;
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
        res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
        return;
      }

      if (!owner || !repo) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Owner and repository name are required',
            statusCode: 400,
          },
        });
        return;
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
        res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
        return;
      }

      if (!owner || !repo) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Owner and repository name are required',
            statusCode: 400,
          },
        });
        return;
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
        res.status(401).json({
          success: false,
          error: {
            message: 'GitHub access token is required',
            statusCode: 401,
          },
        });
        return;
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

