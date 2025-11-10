import axios from 'axios';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';

@Service()
export class GitHubService {
  private readonly baseUrl = 'https://api.github.com';

  /**
   * Get user's organizations
   */
  async getOrganizations(accessToken: string) {
    try {
      const response = await axios.get(`${this.baseUrl}/user/orgs`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      return response.data.map((org: any) => ({
        id: org.id,
        login: org.login,
        name: org.name || org.login,
        avatar: org.avatar_url,
        description: org.description,
        type: org.type,
      }));
    } catch (error: any) {
      logger.error('Error fetching GitHub organizations:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch organizations',
        error.response?.status || 500
      );
    }
  }

  /**
   * Get user's own repositories
   */
  async getUserRepos(accessToken: string) {
    try {
      const response = await axios.get(`${this.baseUrl}/user/repos`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
        params: {
          per_page: 100,
          sort: 'updated',
          affiliation: 'owner,collaborator,organization_member',
        },
      });

      return response.data.map((repo: any) => ({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        description: repo.description,
        private: repo.private,
        language: repo.language,
        stars: repo.stargazers_count,
        forks: repo.forks_count,
        defaultBranch: repo.default_branch,
        updatedAt: repo.updated_at,
        url: repo.html_url,
        cloneUrl: repo.clone_url,
        sshUrl: repo.ssh_url,
        owner: {
          login: repo.owner.login,
          avatar: repo.owner.avatar_url,
        },
      }));
    } catch (error: any) {
      logger.error('Error fetching user repositories:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch user repositories',
        error.response?.status || 500
      );
    }
  }

  /**
   * Get all repositories (user's own + organization repos)
   */
  async getAllRepositories(accessToken: string) {
    try {
      const allRepos: any[] = [];

      // Get user's own repositories
      try {
        const userRepos = await this.getUserRepos(accessToken);
        allRepos.push(...userRepos);
      } catch (error: any) {
        logger.warn('Failed to fetch user repositories:', error);
      }

      // Get organization repositories
      try {
        const orgs = await this.getOrganizations(accessToken);
        for (const org of orgs) {
          try {
            const orgRepos = await this.getOrganizationRepos(accessToken, org.login);
            allRepos.push(...orgRepos);
          } catch (error: any) {
            logger.warn(`Failed to fetch repos for org ${org.login}:`, error);
          }
        }
      } catch (error: any) {
        logger.warn('Failed to fetch organizations:', error);
      }

      // Remove duplicates (in case a repo appears in both user and org repos)
      const uniqueRepos = Array.from(
        new Map(allRepos.map(repo => [repo.id, repo])).values()
      );

      return uniqueRepos;
    } catch (error: any) {
      logger.error('Error fetching all repositories:', error);
      throw new CustomError(
        error.message || 'Failed to fetch all repositories',
        error.statusCode || 500
      );
    }
  }

  /**
   * Get repositories for an organization
   */
  async getOrganizationRepos(accessToken: string, orgName: string) {
    try {
      const response = await axios.get(`${this.baseUrl}/orgs/${orgName}/repos`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
        params: {
          per_page: 100,
          sort: 'updated',
        },
      });

      return response.data.map((repo: any) => ({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        description: repo.description,
        private: repo.private,
        language: repo.language,
        stars: repo.stargazers_count,
        forks: repo.forks_count,
        defaultBranch: repo.default_branch,
        updatedAt: repo.updated_at,
        url: repo.html_url,
        cloneUrl: repo.clone_url,
        sshUrl: repo.ssh_url,
      }));
    } catch (error: any) {
      logger.error('Error fetching GitHub repositories:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch repositories',
        error.response?.status || 500
      );
    }
  }

  /**
   * Get repository contents (recursive)
   */
  async getRepositoryContents(
    accessToken: string,
    owner: string,
    repo: string,
    path: string = '',
    branch?: string
  ) {
    try {
      const contents: any[] = [];
      
      const response = await axios.get(
        `${this.baseUrl}/repos/${owner}/${repo}/contents/${path}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
          params: branch ? { ref: branch } : {},
        }
      );

      const items = Array.isArray(response.data) ? response.data : [response.data];

      for (const item of items) {
        if (item.type === 'file') {
          // Get file content
          const fileContent = await this.getFileContent(accessToken, owner, repo, item.path, branch);
          contents.push({
            type: 'file',
            path: item.path,
            name: item.name,
            size: item.size,
            sha: item.sha,
            content: fileContent.content,
            encoding: fileContent.encoding,
            downloadUrl: item.download_url,
            url: item.html_url,
          });
        } else if (item.type === 'dir') {
          // Recursively get directory contents
          const dirContents = await this.getRepositoryContents(
            accessToken,
            owner,
            repo,
            item.path,
            branch
          );
          contents.push({
            type: 'directory',
            path: item.path,
            name: item.name,
            contents: dirContents,
          });
        }
      }

      return contents;
    } catch (error: any) {
      logger.error('Error fetching repository contents:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch repository contents',
        error.response?.status || 500
      );
    }
  }

  /**
   * Get file content
   */
  private async getFileContent(
    accessToken: string,
    owner: string,
    repo: string,
    path: string,
    branch?: string
  ) {
    try {
      const response = await axios.get(
        `${this.baseUrl}/repos/${owner}/${repo}/contents/${path}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
          params: branch ? { ref: branch } : {},
        }
      );

      return {
        content: response.data.content,
        encoding: response.data.encoding,
        size: response.data.size,
      };
    } catch (error: any) {
      logger.error('Error fetching file content:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch file content',
        error.response?.status || 500
      );
    }
  }

  /**
   * Get repository branches
   */
  async getRepositoryBranches(accessToken: string, owner: string, repo: string) {
    try {
      const response = await axios.get(
        `${this.baseUrl}/repos/${owner}/${repo}/branches`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
        }
      );

      return response.data.map((branch: any) => ({
        name: branch.name,
        sha: branch.commit.sha,
        protected: branch.protected,
      }));
    } catch (error: any) {
      logger.error('Error fetching repository branches:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch branches',
        error.response?.status || 500
      );
    }
  }

  /**
   * Get user information
   */
  async getUserInfo(accessToken: string) {
    try {
      const response = await axios.get(`${this.baseUrl}/user`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      return {
        id: response.data.id,
        login: response.data.login,
        name: response.data.name,
        email: response.data.email,
        avatar: response.data.avatar_url,
        bio: response.data.bio,
        company: response.data.company,
        location: response.data.location,
        publicRepos: response.data.public_repos,
        followers: response.data.followers,
        following: response.data.following,
      };
    } catch (error: any) {
      logger.error('Error fetching user info:', error);
      throw new CustomError(
        error.response?.data?.message || 'Failed to fetch user info',
        error.response?.status || 500
      );
    }
  }
}


