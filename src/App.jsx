import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Routes, Route, useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  History, 
  Globe, 
  Database, 
  Search, 
  Upload, 
  AlertTriangle,
  Flame,
  CheckCircle,
  FileSpreadsheet
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://turtleneck-m5bc.onrender.com';

function Dashboard() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [domainInput, setDomainInput] = useState('');
  const [batchInput, setBatchInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [singleResult, setSingleResult] = useState(null);
  const [batchResults, setBatchResults] = useState([]);
  const [isBatchMode, setIsBatchMode] = useState(false);
  
  // Dashboard stats and history
  const [stats, setStats] = useState({
    total_scanned: 0,
    label_counts: { legitimate: 0, phishing: 0 },
    top_risky_tlds: []
  });
  const [history, setHistory] = useState([]);
  const [isLoadingStats, setIsLoadingStats] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // Fetch stats and history
  const fetchStats = async () => {
    setIsLoadingStats(true);
    try {
      const response = await axios.get(`${API_BASE_URL}/api/stats`);
      setStats(response.data);
    } catch (err) {
      console.error('Error fetching stats:', err);
    } finally {
      setIsLoadingStats(false);
    }
  };

  const fetchHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const response = await axios.get(`${API_BASE_URL}/api/history`);
      setHistory(response.data);
    } catch (err) {
      console.error('Error fetching history:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'stats') {
      fetchStats();
    } else if (activeTab === 'history') {
      fetchHistory();
    }
  }, [activeTab]);

  // Wake-up ping to backend
  useEffect(() => {
    axios.get(`${API_BASE_URL}/`).catch(() => {
      // Ignore errors, we just want to ping
    });
  }, []);

  const handleSingleScan = async (e) => {
    e.preventDefault();
    const targetDomain = domainInput.trim();
    if (!targetDomain) return;
    setIsScanning(true);
    setErrorMsg('');
    setSingleResult(null);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/predict`, {
        domain: targetDomain
      });
      setSingleResult(response.data);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.response?.data?.detail || 'Failed to complete domain scanning.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleBatchScan = async (e) => {
    e.preventDefault();
    const domains = batchInput
      .split('\n')
      .map(d => d.trim())
      .filter(d => d.length > 0);
    
    if (domains.length === 0) return;
    
    setIsScanning(true);
    setErrorMsg('');
    setBatchResults([]);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/predict/batch`, {
        domains: domains
      });
      setBatchResults(response.data.predictions);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.response?.data?.detail || 'Failed to run batch scans.');
    } finally {
      setIsScanning(false);
    }
  };

  // Helper for TLD percentage
  const getLegitPercentage = () => {
    const total = stats.label_counts.legitimate + stats.label_counts.phishing;
    if (total === 0) return 50;
    return Math.round((stats.label_counts.legitimate / total) * 100);
  };

  const getPhishPercentage = () => {
    const total = stats.label_counts.legitimate + stats.label_counts.phishing;
    if (total === 0) return 50;
    return Math.round((stats.label_counts.phishing / total) * 100);
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header">
        <div className="logo-container">
          <ShieldAlert className="logo-icon" size={32} />
          <div>
            <h1 className="logo-text">TURTLENECK AI</h1>
            <p style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontWeight: 700, letterSpacing: '0.1em' }}>THREAT INTELLIGENCE SYSTEM</p>
          </div>
        </div>

        <nav className="nav-tabs">
          <button 
            className={`tab-btn ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            <Globe size={16} /> Scanner
          </button>
          <button 
            className={`tab-btn ${activeTab === 'stats' ? 'active' : ''}`}
            onClick={() => setActiveTab('stats')}
          >
            <Activity size={16} /> Dashboard Stats
          </button>
          <button 
            className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            <History size={16} /> Database Logs
          </button>
        </nav>
      </header>

      {/* Main Content Pane */}
      <main>
        {activeTab === 'scanner' && (
          <div className="glass-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div>
                <h2 className="scanner-title">Threat Assessment Console</h2>
                <p className="scanner-desc">Analyze suspicious URLs, identify internationalized homoglyphs, and evaluate domain risk scores in real-time.</p>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button 
                  className={`tab-btn ${!isBatchMode ? 'active' : ''}`}
                  onClick={() => { setIsBatchMode(false); setErrorMsg(''); }}
                  style={{ borderRadius: '0.5rem', padding: '0.35rem 0.85rem', fontSize: '0.75rem' }}
                >
                  Single Domain
                </button>
                <button 
                  className={`tab-btn ${isBatchMode ? 'active' : ''}`}
                  onClick={() => { setIsBatchMode(true); setErrorMsg(''); }}
                  style={{ borderRadius: '0.5rem', padding: '0.35rem 0.85rem', fontSize: '0.75rem' }}
                >
                  Batch Scan
                </button>
              </div>
            </div>

            {errorMsg && (
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '1rem', borderRadius: '0.75rem', color: 'var(--color-phish)', display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
                <AlertTriangle size={18} />
                <span>{errorMsg}</span>
              </div>
            )}

            {!isBatchMode ? (
              /* Single Scan Tab */
              <div>
                <form onSubmit={handleSingleScan} className="input-group">
                  <input 
                    type="text" 
                    className="domain-input"
                    placeholder="Enter suspicious domain (e.g., secure-login-paypal.tk, gооgle.com)..."
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    disabled={isScanning}
                  />
                  <button type="submit" className="scan-btn" disabled={isScanning || !domainInput.trim()}>
                    {isScanning ? 'Analyzing...' : <><Search size={18} /> Inspect</>}
                  </button>
                </form>

                {isScanning && (
                  <div className="loading-container">
                    <svg className="spinner" viewBox="0 0 50 50">
                      <circle className="path" cx="25" cy="25" r="20" fill="none" strokeWidth="5"></circle>
                    </svg>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', fontWeight: 500 }}>Extracting features and running XGBoost classification...</p>
                  </div>
                )}

                {singleResult && (
                  <div className="result-card">
                    {/* Verdict Card */}
                    <div className="result-verdict">
                      <div className={`verdict-glow ${singleResult.label}`} />
                      {singleResult.label === 'phishing' ? (
                        <ShieldAlert size={48} style={{ color: 'var(--color-phish)' }} />
                      ) : (
                        <ShieldCheck size={48} style={{ color: 'var(--color-legit)' }} />
                      )}
                      
                      <span className="verdict-label">Assessment</span>
                      <h3 className={`verdict-status ${singleResult.label}`}>
                        {singleResult.label.toUpperCase()}
                      </h3>
                      
                      {/* Gauge Chart */}
                      <div className="gauge-container">
                        <svg className="gauge-svg" width="100" height="100">
                          <circle className="gauge-bg" cx="50" cy="50" r="40" />
                          <circle 
                            className="gauge-bar" 
                            cx="50" 
                            cy="50" 
                            r="40" 
                            stroke={singleResult.label === 'phishing' ? 'var(--color-phish)' : 'var(--color-legit)'}
                            strokeDasharray={251.2}
                            strokeDashoffset={251.2 - (251.2 * singleResult.confidence)}
                          />
                        </svg>
                        <span className="gauge-text">{Math.round(singleResult.confidence * 100)}%</span>
                      </div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>Confidence Score</span>
                    </div>

                    {/* Features Panel */}
                    <div>
                      <h3 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '1rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.5rem' }}>
                        Analyzed Feature Indicators
                      </h3>
                      
                      {/* Indicators list */}
                      <div className="indicator-list" style={{ marginBottom: '1.5rem' }}>
                        {singleResult.additional_indicators.has_mixed_script && (
                          <span className="indicator-badge triggered">
                            <AlertTriangle size={14} /> Homoglyph / Mixed Script
                          </span>
                        )}
                        {singleResult.additional_indicators.is_ip && (
                          <span className="indicator-badge triggered">
                            <AlertTriangle size={14} /> IP Hostname Used
                          </span>
                        )}
                        {singleResult.additional_indicators.tld_is_risky && (
                          <span className="indicator-badge triggered">
                            <AlertTriangle size={14} /> High-Risk TLD
                          </span>
                        )}
                        {!singleResult.additional_indicators.has_mixed_script && 
                         !singleResult.additional_indicators.is_ip && 
                         !singleResult.additional_indicators.tld_is_risky && (
                          <span className="indicator-badge normal">
                            <CheckCircle size={14} /> No Suspicious Extra Indicators
                          </span>
                        )}
                      </div>

                      {/* Extracted base features grid */}
                      <div className="features-grid">
                        <div className="feature-pill">
                          <span className="feature-name">Length</span>
                          <span className="feature-value">{singleResult.features.length}</span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">Subdomains</span>
                          <span className="feature-value">{singleResult.features.subdomain_count}</span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">Entropy</span>
                          <span className="feature-value">{singleResult.features.entropy.toFixed(3)}</span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">Brand Matches</span>
                          <span className={`feature-value ${singleResult.features.brand_match ? 'alert' : ''}`}>
                            {singleResult.features.brand_match ? 'YES' : 'NONE'}
                          </span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">Punycode (xn--)</span>
                          <span className={`feature-value ${singleResult.features.has_punycode ? 'alert' : ''}`}>
                            {singleResult.features.has_punycode ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">Login Keyword</span>
                          <span className={`feature-value ${singleResult.features.has_login ? 'alert' : ''}`}>
                            {singleResult.features.has_login ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">Secure Keyword</span>
                          <span className={`feature-value ${singleResult.features.has_secure ? 'alert' : ''}`}>
                            {singleResult.features.has_secure ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="feature-pill">
                          <span className="feature-name">TLD Extension</span>
                          <span className="feature-value" style={{ color: 'var(--accent-cyan)' }}>
                            .{singleResult.features.tld}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              /* Batch Scan Tab */
              <div>
                <form onSubmit={handleBatchScan}>
                  <textarea 
                    className="domain-input"
                    rows={6}
                    style={{ width: '100%', resize: 'vertical', display: 'block', marginBottom: '1rem', fontFamily: 'monospace' }}
                    placeholder="Enter domains, one per line (e.g.&#10;google.com&#10;secure-sbi-login.xyz&#10;paypal-update-account.cam)"
                    value={batchInput}
                    onChange={(e) => setBatchInput(e.target.value)}
                    disabled={isScanning}
                  />
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                      Ready to batch analyze multiple URLs in a single request.
                    </p>
                    <button type="submit" className="scan-btn" disabled={isScanning || !batchInput.trim()}>
                      {isScanning ? 'Scanning Batch...' : <><Search size={18} /> Inspect Batch</>}
                    </button>
                  </div>
                </form>

                {isScanning && (
                  <div className="loading-container">
                    <svg className="spinner" viewBox="0 0 50 50">
                      <circle className="path" cx="25" cy="25" r="20" fill="none" strokeWidth="5"></circle>
                    </svg>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Performing batch predictions and saving logs to database...</p>
                  </div>
                )}

                {batchResults.length > 0 && (
                  <div style={{ marginTop: '2rem' }}>
                    <h3 style={{ fontSize: '1.125rem', fontWeight: 700, borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.5rem' }}>
                      Batch Scan Results ({batchResults.length} analyzed)
                    </h3>
                    <div className="batch-results-list">
                      {batchResults.map((res, i) => (
                        <div key={i} className="batch-result-item">
                          <div>
                            <span className="batch-domain-name">{res.domain}</span>
                            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                              {res.additional_indicators.has_mixed_script && (
                                <span style={{ fontSize: '0.65rem', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--color-phish)', padding: '0.1rem 0.35rem', borderRadius: '0.25rem', fontWeight: 600 }}>Homoglyph</span>
                              )}
                              {res.additional_indicators.tld_is_risky && (
                                <span style={{ fontSize: '0.65rem', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--color-phish)', padding: '0.1rem 0.35rem', borderRadius: '0.25rem', fontWeight: 600 }}>Risky TLD</span>
                              )}
                            </div>
                          </div>
                          <div className="batch-meta">
                            <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                              {Math.round(res.confidence * 100)}% Match
                            </span>
                            <span className={`badge ${res.label}`}>
                              {res.label}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'stats' && (
          <div>
            {isLoadingStats ? (
              <div className="loading-container">
                <svg className="spinner" viewBox="0 0 50 50">
                  <circle className="path" cx="25" cy="25" r="20" fill="none" strokeWidth="5"></circle>
                </svg>
                <p style={{ color: 'var(--text-secondary)' }}>Aggregating system statistics...</p>
              </div>
            ) : (
              <div>
                {/* Stats Summary Cards */}
                <div className="stats-summary">
                  <div className="stat-card">
                    <Database className="stat-icon" size={24} />
                    <div className="stat-details">
                      <h4>Total Analyzed</h4>
                      <span>{stats.total_scanned}</span>
                    </div>
                  </div>
                  <div className="stat-card">
                    <ShieldCheck className="stat-icon legit" size={24} />
                    <div className="stat-details">
                      <h4>Legitimate</h4>
                      <span>{stats.label_counts.legitimate}</span>
                    </div>
                  </div>
                  <div className="stat-card">
                    <ShieldAlert className="stat-icon phish" size={24} />
                    <div className="stat-details">
                      <h4>Phishing Threat</h4>
                      <span>{stats.label_counts.phishing}</span>
                    </div>
                  </div>
                </div>

                {/* Custom Charts Grid */}
                <div className="analytics-grid">
                  {/* Category Breakdown */}
                  <div className="chart-card">
                    <h3 className="chart-header">Threat vs Legit Ratio</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', justifyContent: 'center', height: '180px' }}>
                      <div className="bar-chart-container">
                        <div className="bar-item">
                          <span className="bar-label">Legit</span>
                          <div className="bar-track">
                            <div className="bar-fill" style={{ width: `${getLegitPercentage()}%` }} />
                          </div>
                          <span className="bar-count">{getLegitPercentage()}%</span>
                        </div>
                        <div className="bar-item">
                          <span className="bar-label">Phishing</span>
                          <div className="bar-track">
                            <div className="bar-fill phish" style={{ width: `${getPhishPercentage()}%` }} />
                          </div>
                          <span className="bar-count">{getPhishPercentage()}%</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Top Risky TLDs */}
                  <div className="chart-card">
                    <h3 className="chart-header">Top Risky TLD Extensions</h3>
                    {stats.top_risky_tlds.length === 0 ? (
                      <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '3rem 0', fontSize: '0.875rem' }}>
                        No phishing threats identified yet to extract risky TLD data.
                      </p>
                    ) : (
                      <div className="bar-chart-container">
                        {stats.top_risky_tlds.map((item, idx) => {
                          const maxCount = stats.top_risky_tlds[0].count;
                          const barWidth = Math.round((item.count / maxCount) * 100);
                          return (
                            <div key={idx} className="bar-item">
                              <span className="bar-label" style={{ fontFamily: 'monospace' }}>.{item.tld}</span>
                              <div className="bar-track">
                                <div className="bar-fill phish" style={{ width: `${barWidth}%` }} />
                              </div>
                              <span className="bar-count">{item.count}</span>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'history' && (
          <div className="glass-panel">
            <h2 className="scanner-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <History className="logo-icon" size={24} /> Database Scan Logs
            </h2>
            <p className="scanner-desc">View the comprehensive list of previously scanned domains logged to the database.</p>

            {isLoadingHistory ? (
              <div className="loading-container">
                <svg className="spinner" viewBox="0 0 50 50">
                  <circle className="path" cx="25" cy="25" r="20" fill="none" strokeWidth="5"></circle>
                </svg>
                <p style={{ color: 'var(--text-secondary)' }}>Retrieving scan histories...</p>
              </div>
            ) : history.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '4rem 2rem', color: 'var(--text-secondary)' }}>
                <Database size={40} style={{ marginBottom: '1rem', opacity: 0.5 }} />
                <p style={{ fontSize: '0.9375rem' }}>No past lookup logs found in the database.</p>
                <p style={{ fontSize: '0.8125rem', marginTop: '0.25rem' }}>Scan domains under the Scanner tab to populate logs.</p>
              </div>
            ) : (
              <div className="table-wrapper">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th>Domain Name</th>
                      <th>Assessment Label</th>
                      <th>Model Confidence</th>
                      <th>Scan Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((scan, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600, fontFamily: 'monospace' }}>{scan.domain}</td>
                        <td>
                          <span className={`badge ${scan.label}`}>
                            {scan.label}
                          </span>
                        </td>
                        <td className="confidence-cell">
                          {Math.round(scan.confidence * 100)}%
                        </td>
                        <td className="time-cell">
                          {new Date(scan.timestamp).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function NotFound() {
  const navigate = useNavigate();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', textAlign: 'center', color: 'var(--text-primary)' }}>
      <AlertTriangle size={64} style={{ color: 'var(--color-phish)', marginBottom: '1rem' }} />
      <h1 style={{ fontSize: '3rem', marginBottom: '0.5rem' }}>404</h1>
      <p style={{ fontSize: '1.2rem', color: 'var(--text-secondary)', marginBottom: '2rem' }}>Page not found.</p>
      <button onClick={() => navigate('/')} className="scan-btn" style={{ padding: '0.75rem 1.5rem', width: 'auto' }}>
        Go Back to Main Screen
      </button>
    </div>
  );
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default App;
