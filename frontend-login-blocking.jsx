// Enhanced Login Component with Blocking System
import React, { useState, useEffect } from 'react';
import authService from './services/authService';

const Login = ({ onLoginSuccess }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [blockStatus, setBlockStatus] = useState(null);
  const [attemptsRemaining, setAttemptsRemaining] = useState(3);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const checkBlockStatus = async (email) => {
    try {
      const result = await authService.checkBlockStatus(email);
      if (result.success) {
        setBlockStatus(result.data);
        if (result.data.isBlocked) {
          setAttemptsRemaining(0);
        } else {
          setAttemptsRemaining(3 - result.data.attempts);
        }
      }
    } catch (error) {
      console.error('Failed to check block status:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await authService.login(formData.email, formData.password);

      if (result.success) {
        // Check if user is admin
        if (authService.isAdmin()) {
          onLoginSuccess('admin');
        } else {
          onLoginSuccess('user');
        }
      } else {
        // Handle different error types
        if (result.error.code === 'ACCOUNT_BLOCKED') {
          setError(`Account blocked after 3 failed attempts. Please try again in ${result.error.details.remainingMinutes} minutes.`);
          setBlockStatus({
            isBlocked: true,
            remainingMinutes: result.error.details.remainingMinutes,
            attempts: result.error.details.attempts
          });
          setAttemptsRemaining(0);
        } else if (result.error.code === 'INVALID_CREDENTIALS') {
          setError(`Invalid credentials. ${result.error.details.remainingAttempts} attempts remaining.`);
          setAttemptsRemaining(result.error.details.remainingAttempts);
        } else if (result.error.code === 'USER_ALREADY_LOGGED_IN') {
          setError('This account is already logged in on another device. Please logout from the other device first.');
        } else if (result.error.code === 'ADMIN_ACCESS_DENIED') {
          setError('Access denied. Admin login is restricted to authorized personnel only.');
        } else {
          setError(result.error.message || 'Login failed');
        }
      }
    } catch (error) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Check block status when email changes
  useEffect(() => {
    if (formData.email) {
      checkBlockStatus(formData.email);
    }
  }, [formData.email]);

  return (
    <div className="login-container">
      <h2>Login</h2>
      
      {/* Block Status Display */}
      {blockStatus && blockStatus.isBlocked && (
        <div className="block-warning">
          <h3>🚫 Account Blocked</h3>
          <p>This account is temporarily blocked due to multiple failed login attempts.</p>
          <p>Please try again in <strong>{blockStatus.remainingMinutes} minutes</strong>.</p>
          <p>Blocked at: {new Date(blockStatus.blockedAt).toLocaleString()}</p>
          <p>Expires at: {new Date(blockStatus.expiresAt).toLocaleString()}</p>
        </div>
      )}

      {/* Attempts Remaining Display */}
      {!blockStatus?.isBlocked && attemptsRemaining < 3 && (
        <div className="attempts-warning">
          <p>⚠️ {attemptsRemaining} attempts remaining before account is blocked.</p>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Email:</label>
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            required
            disabled={blockStatus?.isBlocked}
          />
        </div>
        
        <div className="form-group">
          <label>Password:</label>
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            required
            disabled={blockStatus?.isBlocked}
          />
        </div>

        {error && <div className="error-message">{error}</div>}

        <button 
          type="submit" 
          disabled={loading || blockStatus?.isBlocked}
        >
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>

      <div className="login-info">
        <h3>Test Accounts:</h3>
        <p><strong>Admin:</strong> webnox@admin.com / 12345</p>
        <p><strong>User:</strong> user1@cyberix.com / user123</p>
        
        <h3>Security Features:</h3>
        <ul>
          <li>✅ Single device login enforcement</li>
          <li>✅ Account blocking after 3 failed attempts</li>
          <li>✅ 5-minute block duration</li>
          <li>✅ Real-time attempt tracking</li>
          <li>✅ Automatic block cleanup</li>
        </ul>
      </div>
    </div>
  );
};

export default Login;
