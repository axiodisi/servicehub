import React, { useState, useEffect } from 'react';
import AuthComponent from './components/AuthComponent';
import LandingPage from './components/LandingPage';

const API_URL = 'https://your-tiny-host-url.com';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [showAuth, setShowAuth] = useState(false);

  useEffect(() => {
    // Check if the user is already authenticated
    const checkAuth = async () => {
      try {
        const response = await fetch(`${API_URL}/check-auth`, {
          method: 'GET',
          credentials: 'include', // Important for sending cookies
        });
        if (response.ok) {
          const userData = await response.json();
          setIsAuthenticated(true);
          setUser(userData);
        }
      } catch (error) {
        console.error('Error checking authentication:', error);
      }
    };
    checkAuth();
  }, []);

  const handleLogout = async () => {
    try {
      await fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include',
      });
      setIsAuthenticated(false);
      setUser(null);
      setShowAuth(false);
    } catch (error) {
      console.error('Error logging out:', error);
    }
  };

  const handleAuthClick = () => {
    setShowAuth(true);
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>ServiceHub</h1>
        {isAuthenticated && user && (
          <p>Welcome, {user.email} <button onClick={handleLogout}>Logout</button></p>
        )}
      </header>
      <main>
        {!isAuthenticated ? (
          showAuth ? (
            <AuthComponent onLoginSuccess={(userData) => {
              setIsAuthenticated(true);
              setUser(userData);
            }} />
          ) : (
            <LandingPage onAuthClick={handleAuthClick} />
          )
        ) : (
          <div>
            {/* Add your main app content here */}
            <h2>Main Content</h2>
            <p>This is where your main application content would go when the user is authenticated.</p>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
