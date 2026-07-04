// web/src/pages/Dashboard.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../components/Modal';

export default function Dashboard({ authToken, onLogout }) {
  const [data, setData] = useState({ customers: [], licenses: [], activations: [], stats: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Modals state
  const [isCustomerModalOpen, setIsCustomerModalOpen] = useState(false);
  const [isLicenseModalOpen, setIsLicenseModalOpen] = useState(false);
  
  // Form values
  const [customerForm, setCustomerForm] = useState({ id: '', name: '', max_licenses: 5 });
  const [licenseForm, setLicenseForm] = useState({ customer_id: '', name: '', trial_days: 30, max_devices: 3, target_fingerprint: '' });

  const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const fetchData = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/admin/stats`, {
        headers: { 'Authorization': `Basic ${authToken}` }
      });
      if (response.ok) {
        const json = await response.json();
        setData(json);
      } else {
        setError('Unauthorized access or server error.');
      }
    } catch (err) {
      setError('Connection to server lost.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [authToken]);

  const handleAddCustomer = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${backendUrl}/api/admin/customer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${authToken}`
        },
        body: JSON.stringify(customerForm)
      });
      if (response.ok) {
        setIsCustomerModalOpen(false);
        setCustomerForm({ id: '', name: '', max_licenses: 5 });
        fetchData();
      } else {
        const err = await response.json();
        alert(err.detail || 'Failed to create customer');
      }
    } catch (err) {
      alert('Network failure creating customer');
    }
  };

  const handleIssueLicense = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${backendUrl}/api/admin/license`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${authToken}`
        },
        body: JSON.stringify({
          ...licenseForm,
          target_fingerprint: licenseForm.target_fingerprint || null
        })
      });
      if (response.ok) {
        setIsLicenseModalOpen(false);
        setLicenseForm({ customer_id: '', name: '', trial_days: 30, max_devices: 3, target_fingerprint: '' });
        fetchData();
      } else {
        const err = await response.json();
        alert(err.detail || 'Failed to generate license');
      }
    } catch (err) {
      alert('Network failure generating license');
    }
  };

  const handleRevokeLicense = async (licenseId) => {
    if (!confirm(`Are you absolutely sure you want to revoke license ${licenseId}?`)) return;
    try {
      const response = await fetch(`${backendUrl}/api/admin/license/revoke/${licenseId}`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${authToken}` }
      });
      if (response.ok) {
        fetchData();
      } else {
        alert('Failed to revoke license');
      }
    } catch (err) {
      alert('Network error revoking license');
    }
  };

  if (loading) {
    return <div style={styles.loading}>Resolving KMS registry...</div>;
  }

  return (
    <div style={styles.container}>
      {/* Header bar */}
      <header style={styles.header} className="glass-panel">
        <div style={styles.headerBrand}>
          <span style={{ fontSize: '1.5rem' }}>🛡️</span>
          <div>
            <h1 style={styles.headerTitle}>Vajraa KMS</h1>
            <p style={styles.headerSubtitle}>Key Management & Verification Console</p>
          </div>
        </div>
        <button className="btn btn-secondary" onClick={onLogout}>Sign Out</button>
      </header>

      {error && <div className="btn btn-danger" style={{ margin: '20px 0', width: '100%' }}>{error}</div>}

      {/* Grid of Stats Cards */}
      <div style={styles.statsGrid}>
        <div className="glass-panel" style={styles.statCard}>
          <div style={styles.statLabel}>Total Customers</div>
          <div style={styles.statValue}>{data.stats?.total_customers || 0}</div>
        </div>
        <div className="glass-panel" style={styles.statCard}>
          <div style={styles.statLabel}>Active Licenses</div>
          <div style={styles.statValue}>{data.stats?.total_licenses || 0}</div>
        </div>
        <div className="glass-panel" style={styles.statCard}>
          <div style={styles.statLabel}>Total Activations</div>
          <div style={styles.statValue}>{data.stats?.total_activations || 0}</div>
        </div>
        <div className="glass-panel" style={styles.statCard}>
          <div style={styles.statLabel}>Bound Hardware</div>
          <div style={styles.statValue}>{data.stats?.active_devices || 0}</div>
        </div>
      </div>

      {/* Actions */}
      <div style={styles.actionBar}>
        <button className="btn btn-primary" onClick={() => setIsCustomerModalOpen(true)}>+ Register Customer</button>
        <button className="btn btn-primary" onClick={() => setIsLicenseModalOpen(true)}>+ Issue Model Lease</button>
      </div>

      {/* Customers Section */}
      <section style={styles.section} className="glass-panel">
        <h2 style={styles.sectionTitle}>Registered Customers</h2>
        <div className="custom-table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Customer ID</th>
                <th>Company Name</th>
                <th>License Quota</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {data.customers.length === 0 ? (
                <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No customers registered.</td></tr>
              ) : data.customers.map(c => (
                <tr key={c.id}>
                  <td><code style={{ fontSize: '0.85rem' }}>{c.id}</code></td>
                  <td style={{ fontWeight: '500' }}>{c.name}</td>
                  <td>{c.max_licenses} Licenses</td>
                  <td>{new Date(c.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Licenses Section */}
      <section style={styles.section} className="glass-panel">
        <h2 style={styles.sectionTitle}>Active Licenses & Leases</h2>
        <div className="custom-table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>License Key</th>
                <th>Customer ID</th>
                <th>Model Target</th>
                <th>Quota Limit</th>
                <th>Expiration Date</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.licenses.length === 0 ? (
                <tr><td colSpan="7" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No leases generated.</td></tr>
              ) : data.licenses.map(l => (
                <tr key={l.id}>
                  <td><code style={{ fontSize: '0.85rem' }}>{l.id}</code></td>
                  <td>{l.customer_id}</td>
                  <td style={{ fontWeight: '500' }}>{l.name}</td>
                  <td>{l.max_devices} Devices</td>
                  <td>{new Date(l.expires_at).toLocaleDateString()}</td>
                  <td>
                    {l.is_revoked ? (
                      <span style={{ color: 'var(--danger)', fontWeight: '600' }}>Revoked</span>
                    ) : new Date(l.expires_at) < new Date() ? (
                      <span style={{ color: '#eab308', fontWeight: '600' }}>Expired</span>
                    ) : (
                      <span style={{ color: 'var(--success)', fontWeight: '600' }}>Active</span>
                    )}
                  </td>
                  <td>
                    {!l.is_revoked && (
                      <button className="btn btn-danger" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={() => handleRevokeLicense(l.id)}>Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Activations Section */}
      <section style={styles.section} className="glass-panel">
        <h2 style={styles.sectionTitle}>Active Device Registrations</h2>
        <div className="custom-table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Activation ID</th>
                <th>License Key</th>
                <th>Hardware Hash</th>
                <th>Activation Code</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {data.activations.length === 0 ? (
                <tr><td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No devices activated yet.</td></tr>
              ) : data.activations.map(a => (
                <tr key={a.id}>
                  <td><code>{a.id}</code></td>
                  <td><code>{a.license_id}</code></td>
                  <td><code style={{ color: 'var(--text-secondary)' }}>{a.hardware_hash.slice(0, 16)}...</code></td>
                  <td><strong style={{ color: 'var(--accent-secondary)' }}>{a.activation_code}</strong></td>
                  <td>{new Date(a.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Add Customer Modal */}
      <Modal isOpen={isCustomerModalOpen} onClose={() => setIsCustomerModalOpen(false)} title="Register New Customer">
        <form onSubmit={handleAddCustomer}>
          <div className="form-group">
            <label className="form-label">Customer ID (Unique Identifier)</label>
            <input
              type="text"
              className="form-control"
              placeholder="e.g. ACME-CORP"
              value={customerForm.id}
              onChange={(e) => setCustomerForm({ ...customerForm, id: e.target.value.toUpperCase() })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Company / Client Name</label>
            <input
              type="text"
              className="form-control"
              placeholder="Acme Corporation Ltd."
              value={customerForm.name}
              onChange={(e) => setCustomerForm({ ...customerForm, name: e.target.value })}
              required
            />
          </div>
          <div className="form-group" style={{ marginBottom: '24px' }}>
            <label className="form-label">Max Licenses Permitted</label>
            <input
              type="number"
              className="form-control"
              min="1"
              value={customerForm.max_licenses}
              onChange={(e) => setCustomerForm({ ...customerForm, max_licenses: parseInt(e.target.value) })}
              required
            />
          </div>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-secondary" onClick={() => setIsCustomerModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary">Create Customer</button>
          </div>
        </form>
      </Modal>

      {/* Issue License Modal */}
      <Modal isOpen={isLicenseModalOpen} onClose={() => setIsLicenseModalOpen(false)} title="Issue Model License Lease">
        <form onSubmit={handleIssueLicense}>
          <div className="form-group">
            <label className="form-label">Select Customer ID</label>
            <select
              className="form-control"
              value={licenseForm.customer_id}
              onChange={(e) => setLicenseForm({ ...licenseForm, customer_id: e.target.value })}
              required
            >
              <option value="">-- Choose Customer --</option>
              {data.customers.map(c => (
                <option key={c.id} value={c.id}>{c.name} ({c.id})</option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Application / Model Name</label>
            <input
              type="text"
              className="form-control"
              placeholder="e.g. Llama-3-8B-Instruct"
              value={licenseForm.name}
              onChange={(e) => setLicenseForm({ ...licenseForm, name: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Trial Duration (Days)</label>
            <input
              type="number"
              className="form-control"
              min="1"
              value={licenseForm.trial_days}
              onChange={(e) => setLicenseForm({ ...licenseForm, trial_days: parseInt(e.target.value) })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Max Bound Devices</label>
            <input
              type="number"
              className="form-control"
              min="1"
              value={licenseForm.max_devices}
              onChange={(e) => setLicenseForm({ ...licenseForm, max_devices: parseInt(e.target.value) })}
              required
            />
          </div>
          <div className="form-group" style={{ marginBottom: '24px' }}>
            <label className="form-label">Pre-Bound Hardware Fingerprint (Optional)</label>
            <input
              type="text"
              className="form-control"
              placeholder="Leave empty for dynamic activation"
              value={licenseForm.target_fingerprint}
              onChange={(e) => setLicenseForm({ ...licenseForm, target_fingerprint: e.target.value })}
            />
          </div>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-secondary" onClick={() => setIsLicenseModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary">Generate Lease</button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

const styles = {
  container: {
    padding: '30px',
    maxWidth: '1200px',
    margin: '0 auto',
    width: '100%'
  },
  loading: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '100vh',
    fontSize: '1.2rem',
    color: 'var(--text-secondary)'
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '20px 30px',
    marginBottom: '30px',
    backgroundColor: 'rgba(15, 23, 42, 0.6)'
  },
  headerBrand: {
    display: 'flex',
    alignItems: 'center',
    gap: '15px',
    textAlign: 'left'
  },
  headerTitle: {
    fontSize: '1.5rem',
    fontWeight: '600',
    color: '#fff',
    lineHeight: '1.2'
  },
  headerSubtitle: {
    fontSize: '0.85rem',
    color: 'var(--text-secondary)'
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '20px',
    marginBottom: '30px'
  },
  statCard: {
    padding: '24px',
    textAlign: 'left'
  },
  statLabel: {
    fontSize: '0.85rem',
    color: 'var(--text-secondary)',
    marginBottom: '10px',
    fontWeight: '500',
    textTransform: 'uppercase',
    letterSpacing: '0.5px'
  },
  statValue: {
    fontSize: '2.25rem',
    fontFamily: 'var(--font-heading)',
    fontWeight: '700',
    color: '#fff'
  },
  actionBar: {
    display: 'flex',
    gap: '16px',
    marginBottom: '30px'
  },
  section: {
    padding: '24px',
    marginBottom: '30px',
    backgroundColor: 'rgba(15, 23, 42, 0.4)'
  },
  sectionTitle: {
    fontSize: '1.15rem',
    fontWeight: '600',
    color: '#fff',
    marginBottom: '20px',
    textAlign: 'left'
  }
};
