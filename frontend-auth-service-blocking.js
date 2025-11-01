// Enhanced AuthService with Blocking System
class AuthService {
  constructor() {
    this.baseURL = 'http://localhost:3000'; // Your backend URL
  }

  // Login function with blocking support
  async login(email, password, deviceInfo = null) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include', // Important for cookies
        body: JSON.stringify({
          email,
          password,
          deviceInfo: deviceInfo || navigator.userAgent
        })
      });

      const data = await response.json();

      if (data.success) {
        // Store user data in localStorage
        localStorage.setItem('user', JSON.stringify(data.data.user));
        localStorage.setItem('userRole', data.data.user.role);
        localStorage.setItem('userEmail', data.data.user.email);
        
        return {
          success: true,
          user: data.data.user,
          message: data.message
        };
      } else {
        return {
          success: false,
          error: data.error
        };
      }
    } catch (error) {
      return {
        success: false,
        error: {
          message: 'Network error',
          statusCode: 500
        }
      };
    }
  }

  // Check block status for an email
  async checkBlockStatus(email) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/block-status/${email}`, {
        method: 'GET',
        credentials: 'include'
      });

      const data = await response.json();
      return data;
    } catch (error) {
      return {
        success: false,
        error: 'Failed to check block status'
      };
    }
  }

  // Logout function
  async logout() {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include'
      });

      const data = await response.json();

      if (data.success) {
        // Clear local storage
        localStorage.removeItem('user');
        localStorage.removeItem('userRole');
        localStorage.removeItem('userEmail');
        
        return {
          success: true,
          message: data.message
        };
      }
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }

  // Check if user is admin
  isAdmin() {
    const userRole = localStorage.getItem('userRole');
    const userEmail = localStorage.getItem('userEmail');
    return userRole === 'ADMIN' && userEmail === 'webnox@admin.com';
  }

  // Check if user is logged in
  isLoggedIn() {
    return localStorage.getItem('user') !== null;
  }

  // Get current user
  getCurrentUser() {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  }

  // Check session status
  async checkSessionStatus() {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/session-status`, {
        credentials: 'include'
      });

      const data = await response.json();
      return data;
    } catch (error) {
      return { success: false, error: 'Session check failed' };
    }
  }

  // Get login logs (Admin only)
  async getLoginLogs(page = 1, limit = 10, userId = null) {
    try {
      let url = `${this.baseURL}/api/auth/login-logs?page=${page}&limit=${limit}`;
      if (userId) {
        url += `&userId=${userId}`;
      }

      const response = await fetch(url, {
        credentials: 'include'
      });

      const data = await response.json();
      return data;
    } catch (error) {
      return { success: false, error: 'Failed to get login logs' };
    }
  }

  // Force logout user (Admin only)
  async forceLogoutUser(userId, reason = 'Admin forced logout') {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/force-logout/${userId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ reason })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      return { success: false, error: 'Failed to force logout user' };
    }
  }

  // Logout all devices
  async logoutAllDevices() {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/logout-all`, {
        method: 'POST',
        credentials: 'include'
      });

      const data = await response.json();
      
      if (data.success) {
        // Clear local storage
        localStorage.removeItem('user');
        localStorage.removeItem('userRole');
        localStorage.removeItem('userEmail');
      }
      
      return data;
    } catch (error) {
      return { success: false, error: 'Failed to logout all devices' };
    }
  }
}

// Export the service
export default new AuthService();
