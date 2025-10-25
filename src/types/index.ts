export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: {
    message: string;
    statusCode?: number;
    details?: any;
  };
  pagination?: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface PaginationQuery {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface SearchQuery extends PaginationQuery {
  search?: string;
  filters?: Record<string, any>;
}

export interface UserPayload {
  id: string;
  email: string;
  role: string;
  isActive: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
}

export interface UpdateUserData {
  email?: string;
  password?: string;
}

export interface CreatePostData {
  title: string;
  content: string;
  published?: boolean;
  tagIds?: string[];
}

export interface UpdatePostData {
  title?: string;
  content?: string;
  published?: boolean;
  tagIds?: string[];
}

export interface CreateCommentData {
  content: string;
  postId: string;
}

export interface UpdateCommentData {
  content: string;
}
