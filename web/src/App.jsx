// web/src/App.jsx
import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Activate from './pages/Activate';

function App() {
  const [authToken, setAuthToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('admin_auth_token');
    if (token) {
      setAuthToken(token);
    }
    setLoading(false);
  }, []);

  const handleLogin = (token) => {
    setAuthToken(token);
  };

  const handleLogout = () => {
    localStorage.removeItem('admin_auth_token');
    setAuthToken(null);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', color: 'var(--text-secondary)' }}>
        Loading Session...
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        {/* Offline activation scanning routing (Public) */}
        <Route path="/activate" element={<Activate />} />

        {/* Dashboard route (Protected by basic auth validation) */}
        <Route 
          path="/" 
          element={
            authToken ? (
              <Dashboard authToken={authToken} onLogout={handleLogout} />
            ) : (
              <Navigate to="/login" replace />
            )
          } 
        />

        {/* Login Page */}
        <Route 
          path="/login" 
          element={
            authToken ? (
              <Navigate to="/" replace />
            ) : (
              <Login onLoginSuccess={handleLogin} />
            )
          } 
        />

        {/* Catch-all fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
