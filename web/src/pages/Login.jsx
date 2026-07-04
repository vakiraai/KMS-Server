// web/src/pages/Login.jsx
import React, { useState } from 'react';

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const token = btoa(`${username}:${password}`);
    const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

    try {
      const response = await fetch(`${backendUrl}/api/admin/stats`, {
        method: 'GET',
        headers: {
          'Authorization': `Basic ${token}`
        }
      });

      if (response.ok) {
        localStorage.setItem('admin_auth_token', token);
        onLoginSuccess(token);
      } else {
        setError('Invalid username or password credentials.');
      }
    } catch (err) {
      setError('Cannot connect to the KMS backend server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div className="glass-panel" style={styles.card}>
        <div style={styles.header}>
          <div style={styles.logo}>🛡️</div>
          <h2 style={styles.title}>Vajraa KMS Portal</h2>
          <p style={styles.subtitle}>Enter credentials to access Key Management Server</p>
        </div>

        {error && (
          <div style={styles.errorAlert}>
            <span>⚠️</span> {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Admin Username</label>
            <input
              type="text"
              className="form-control"
              placeholder="e.g. admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="form-group" style={{ marginBottom: '30px' }}>
            <label className="form-label">Password</label>
            <input
              type="password"
              className="form-control"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', height: '48px' }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '100vh',
    padding: '20px'
  },
  card: {
    width: '100%',
    maxWidth: '420px',
    padding: '40px',
    textAlign: 'center',
    backgroundColor: 'rgba(15, 23, 42, 0.7)'
  },
  header: {
    marginBottom: '32px'
  },
  logo: {
    fontSize: '3rem',
    marginBottom: '16px'
  },
  title: {
    fontFamily: 'var(--font-heading)',
    fontSize: '1.75rem',
    fontWeight: '600',
    marginBottom: '8px',
    color: '#fff'
  },
  subtitle: {
    color: 'var(--text-secondary)',
    fontSize: '0.9rem'
  },
  errorAlert: {
    background: 'var(--danger-bg)',
    border: '1px solid var(--danger)',
    color: '#fff',
    padding: '12px 16px',
    borderRadius: 'var(--border-radius-md)',
    fontSize: '0.9rem',
    marginBottom: '24px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    textAlign: 'left'
  }
};
