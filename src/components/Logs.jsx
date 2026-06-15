import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { History, Database } from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://turtleneck-m5bc.onrender.com';

function Logs() {
  const [history, setHistory] = useState([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);

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
    fetchHistory();
  }, []);

  return (
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
  );
}

export default Logs;
