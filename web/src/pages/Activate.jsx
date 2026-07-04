// web/src/pages/Activate.jsx
import React, { useState, useEffect } from 'react';

export default function Activate() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  
  const [activationCode, setActivationCode] = useState('');
  const [activationToken, setActivationToken] = useState('');
  const [licenseName, setLicenseName] = useState('');
  const [customerId, setCustomerId] = useState('');
  const [copiedCode, setCopiedCode] = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);

  const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const dataParam = params.get('data');

    if (!dataParam) {
      setError('Invalid URL parameters. No QR activation payload detected.');
      setLoading(false);
      return;
    }

    const triggerActivation = async () => {
      try {
        const response = await fetch(`${backendUrl}/api/activate/offline`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ data: dataParam })
        });

        if (response.ok) {
          const res = await response.json();
          setActivationCode(res.activation_code);
          setActivationToken(res.activation_token);
          setLicenseName(res.license_name);
          setCustomerId(res.customer_id);
          setSuccess(true);
        } else {
          const res = await response.json();
          setError(res.detail || 'Activation request was rejected by server.');
        }
      } catch (err) {
        setError('Unable to contact the licensing backend server.');
      } finally {
        setLoading(false);
      }
    };

    triggerActivation();
  }, []);

  const copyToClipboard = (text, setCopiedFlag) => {
    navigator.clipboard.writeText(text);
    setCopiedFlag(true);
    setTimeout(() => setCopiedFlag(false), 2000);
  };

  if (loading) {
    return (
      <div style={styles.container}>
        <div className="glass-panel" style={styles.card}>
          <h2 style={styles.title}>Verifying Hardware...</h2>
          <p style={styles.subtitle}>Securing dynamic envelope lease. Please hold.</p>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div className="glass-panel" style={styles.card}>
        <div style={styles.logo}>🛡️</div>
        
        {error ? (
          <div>
            <h2 style={{ ...styles.title, color: 'var(--danger)' }}>Activation Failed</h2>
            <div style={styles.errorBox}>{error}</div>
            <p style={styles.subtitle}>Please check your license key status or contact your systems administrator.</p>
          </div>
        ) : (
          <div>
            <h2 style={styles.title}>Device Activated!</h2>
            <p style={{ ...styles.subtitle, marginBottom: '24px' }}>
              Lease verified for <strong>{licenseName}</strong> (Client: {customerId})
            </p>

            {/* Verification Code Box */}
            <div style={styles.codeContainer}>
              <div style={styles.codeLabel}>16-Character Activation Code</div>
              <div style={styles.codeDisplay}>{activationCode}</div>
              <button
                className="btn btn-secondary"
                style={{ width: '100%', justifyContent: 'center', marginTop: '12px' }}
                onClick={() => copyToClipboard(activationCode, setCopiedCode)}
              >
                {copiedCode ? '✓ Copied Code' : 'Copy Code'}
              </button>
            </div>

            {/* Token details */}
            <div style={{ marginTop: '24px', textAlign: 'left' }}>
              <div style={styles.codeLabel}>Complete Activation Token</div>
              <textarea
                readOnly
                className="form-control"
                style={styles.tokenArea}
                value={activationToken}
              />
              <button
                className="btn btn-primary"
                style={{ width: '100%', justifyContent: 'center', marginTop: '12px' }}
                onClick={() => copyToClipboard(activationToken, setCopiedToken)}
              >
                {copiedToken ? '✓ Copied Token' : 'Copy Complete Token'}
              </button>
            </div>
            
            <p style={styles.footerNote}>
              Enter this code/token into your offline terminal prompt to unlock inference weights.
            </p>
          </div>
        )}
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
    maxWidth: '480px',
    padding: '40px',
    textAlign: 'center',
    backgroundColor: 'rgba(15, 23, 42, 0.85)'
  },
  logo: {
    fontSize: '3rem',
    marginBottom: '20px'
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
    fontSize: '0.9rem',
    lineHeight: '1.4'
  },
  errorBox: {
    background: 'var(--danger-bg)',
    border: '1px solid var(--danger)',
    color: '#fff',
    padding: '16px',
    borderRadius: 'var(--border-radius-md)',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.85rem',
    margin: '24px 0',
    wordBreak: 'break-all'
  },
  codeContainer: {
    background: 'rgba(99, 102, 241, 0.1)',
    border: '1px solid var(--panel-border-glow)',
    borderRadius: 'var(--border-radius-lg)',
    padding: '24px',
    marginTop: '20px'
  },
  codeLabel: {
    fontSize: '0.8rem',
    textTransform: 'uppercase',
    color: 'var(--text-secondary)',
    letterSpacing: '0.5px',
    marginBottom: '8px',
    fontWeight: '600'
  },
  codeDisplay: {
    fontSize: '1.8rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: '700',
    color: '#fff',
    letterSpacing: '2px'
  },
  tokenArea: {
    height: '100px',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem',
    resize: 'none',
    backgroundColor: 'rgba(15, 23, 42, 0.9)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    marginTop: '8px'
  },
  footerNote: {
    marginTop: '24px',
    fontSize: '0.8rem',
    color: 'var(--text-muted)',
    lineHeight: '1.4'
  }
};
