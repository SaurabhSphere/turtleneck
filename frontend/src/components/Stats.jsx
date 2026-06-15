import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Database, ShieldCheck, ShieldAlert, Flame } from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://turtleneck-m5bc.onrender.com';

function Stats() {
  const [stats, setStats] = useState({
    total_scanned: 0,
    label_counts: { legitimate: 0, phishing: 0 },
    top_risky_tlds: []
  });
  const [isLoadingStats, setIsLoadingStats] = useState(false);
  const [retrainMsg, setRetrainMsg] = useState('');
  const [isRetraining, setIsRetraining] = useState(false);

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

  useEffect(() => {
    fetchStats();
  }, []);

  const handleRetrain = async () => {
    setIsRetraining(true);
    setRetrainMsg('');
    try {
      const response = await axios.post(`${API_BASE_URL}/api/retrain`);
      setRetrainMsg(response.data.message);
    } catch (err) {
      console.error(err);
      setRetrainMsg(err.response?.data?.detail || 'Failed to trigger retraining.');
    } finally {
      setIsRetraining(false);
    }
  };

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

          {/* Admin Panel: Active Learning */}
          <div className="chart-card" style={{ marginTop: '2rem', border: '1px solid rgba(139, 92, 246, 0.3)', background: 'rgba(139, 92, 246, 0.05)' }}>
            <h3 className="chart-header" style={{ color: 'var(--accent-purple)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Flame size={18} /> Active Learning Engine
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Manually trigger a background job to retrain the XGBoost model using the latest user-reported mistakes. This ensures the model dynamically adapts to zero-day phishing trends.
            </p>
            <button 
              className="scan-btn" 
              onClick={handleRetrain} 
              disabled={isRetraining}
              style={{ width: 'auto', padding: '0.5rem 1rem', fontSize: '0.875rem' }}
            >
              {isRetraining ? 'Triggering...' : 'Trigger Model Retraining'}
            </button>
            {retrainMsg && (
              <p style={{ fontSize: '0.875rem', marginTop: '1rem', color: retrainMsg.includes('Failed') ? 'var(--color-phish)' : 'var(--color-legit)' }}>
                {retrainMsg}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Stats;
