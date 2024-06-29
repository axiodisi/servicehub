import React, { useState, useEffect } from 'react';
//import { Alert, AlertDescription } from '@/components/ui/alert';

const API_URL = 'tan-lauralee-4.tiiny.site';

const AuthComponent = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [message, setMessage] = useState('');
  const [currentView, setCurrentView] = useState('login'); // 'login', 'signup', 'resetPassword', 'updatePassword'

  useEffect(() => {
    const checkLoginStatus = async () => {
      try {
        const response = await fetch(`${API_URL}/check-auth`, {
          method: 'GET',
          credentials: 'include', // This is important for including cookies
        });
        if (response.ok) {
          setIsLoggedIn(true);
          setCurrentView('updatePassword');
        }
      } catch (error) {
        console.error('Error checking authentication status:', error);
      }
    };

    checkLoginStatus();
  }, []);

  useEffect(() => {
    const refreshToken = async () => {
      try {
        const response = await fetch(`${API_URL}/refresh-token`, {
          method: 'POST',
          credentials: 'include',
        });
        if (!response.ok) {
          setIsLoggedIn(false);
          setCurrentView('login');
        }
      } catch (error) {
        console.error('Error refreshing token:', error);
      }
    };

    if (isLoggedIn) {
      const intervalId = setInterval(refreshToken, 14 * 60 * 1000); // Refresh every 14 minutes
      return () => clearInterval(intervalId);
    }
  }, [isLoggedIn]);

  const handleSignUp = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setCurrentView('login');
      } else {
        setMessage(data.error);
      }
    } catch (error) {
      setMessage('An error occurred during sign up');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
      });
      const data = await response.json();
      if (response.ok) {
        setIsLoggedIn(true);
        setMessage('Logged in successfully');
        setCurrentView('updatePassword');
      } else {
        setMessage(data.error);
      }
    } catch (error) {
      setMessage('An error occurred during login');
    }
  };

  const handleLogout = async () => {
    try {
      const response = await fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include',
      });
      if (response.ok) {
        setIsLoggedIn(false);
        setEmail('');
        setPassword('');
        setMessage('Logged out successfully');
        setCurrentView('login');
      } else {
        const data = await response.json();
        setMessage(data.error);
      }
    } catch (error) {
      setMessage('An error occurred during logout');
    }
  };

  const handleUpdatePassword = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/update-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: password, newPassword }),
        credentials: 'include',
      });
      const data = await response.json();
      if (response.ok) {
        setMessage('Password updated successfully');
        setPassword('');
        setNewPassword('');
      } else {
        setMessage(data.error);
      }
    } catch (error) {
      setMessage('An error occurred while updating password');
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
        credentials: 'include',
      });
      const data = await response.json();
      if (response.ok) {
        setMessage('Password reset instructions sent to your email');
      } else {
        setMessage(data.error);
      }
    } catch (error) {
      setMessage('An error occurred while resetting password');
    }
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-xl">
      {message && (
        //<Alert className="mb-4">
        //<AlertDescription>{message}</AlertDescription>
        //</Alert>
        <div className='mb-4'>{message}</div>
      )}

      {!isLoggedIn ? (
        currentView === 'login' ? (
          <>
            <form onSubmit={handleLogin}>
              <h2 className="text-xl font-bold mb-4">Login</h2>
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full p-2 mb-2 border rounded"
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full p-2 mb-2 border rounded"
                required
              />
              <button type="submit" className="w-full p-2 bg-green-500 text-white rounded">
                Login
              </button>
            </form>
            <button onClick={() => setCurrentView('signup')} className="w-full p-2 mt-2 bg-blue-500 text-white rounded">
              Sign Up
            </button>
            <button onClick={() => setCurrentView('resetPassword')} className="w-full p-2 mt-2 bg-yellow-500 text-white rounded">
              Reset Password
            </button>
          </>
        ) : currentView === 'signup' ? (
          <form onSubmit={handleSignUp}>
            <h2 className="text-xl font-bold mb-4">Sign Up</h2>
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full p-2 mb-2 border rounded"
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full p-2 mb-2 border rounded"
              required
              minLength={8}
            />
            <button type="submit" className="w-full p-2 bg-blue-500 text-white rounded">
              Sign Up
            </button>
            <button onClick={() => setCurrentView('login')} className="w-full p-2 mt-2 bg-gray-500 text-white rounded">
              Back to Login
            </button>
          </form>
        ) : (
          <form onSubmit={handleResetPassword}>
            <h2 className="text-xl font-bold mb-4">Reset Password</h2>
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full p-2 mb-2 border rounded"
              required
            />
            <button type="submit" className="w-full p-2 bg-yellow-500 text-white rounded">
              Reset Password
            </button>
            <button onClick={() => setCurrentView('login')} className="w-full p-2 mt-2 bg-gray-500 text-white rounded">
              Back to Login
            </button>
          </form>
        )
      ) : (
        <>
          <h2 className="text-xl font-bold mb-4">Welcome, {email}</h2>
          <button onClick={handleLogout} className="w-full p-2 mb-4 bg-red-500 text-white rounded">
            Logout
          </button>

          <form onSubmit={handleUpdatePassword}>
            <h2 className="text-xl font-bold mb-4">Update Password</h2>
            <input
              type="password"
              placeholder="Current Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full p-2 mb-2 border rounded"
              required
            />
            <input
              type="password"
              placeholder="New Password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full p-2 mb-2 border rounded"
              required
              minLength={8}
            />
            <button type="submit" className="w-full p-2 bg-yellow-500 text-white rounded">
              Update Password
            </button>
          </form>
        </>
      )}
    </div>
  );
};

export default AuthComponent;
