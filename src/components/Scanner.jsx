import React, { useState } from 'react';
import axios from 'axios';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  AlertTriangle, 
  CheckCircle 
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://turtleneck-m5bc.onrender.com';

function isValidUrlOrDomain(input) {
  if (!input) return false;
  let cleaned = input.trim();
  
  // Reject if contains whitespace
  if (/\s/.test(cleaned)) return false;
  
  // Remove protocol
  cleaned = cleaned.replace(/^https?:\/\//i, '');
  // Remove path, query string, port
  cleaned = cleaned.split('/')[0].split(':')[0];
  
  if (!cleaned) return false;
  
  // Check IPv4
  const ipv4Regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(cleaned)) return true;
  
  // Check IPv6 (basic check)
  if (cleaned.includes(':') && !cleaned.includes('.')) {
    const colonCount = (cleaned.match(/:/g) || []).length;
    if (colonCount >= 2 && colonCount <= 7) return true;
  }
  
  // Must contain at least one dot
  const dotIndex = cleaned.lastIndexOf('.');
  if (dotIndex === -1 || dotIndex === 0 || dotIndex === cleaned.length - 1) {
    return false;
  }
  
  const label = cleaned.substring(0, dotIndex);
  const tld = cleaned.substring(dotIndex + 1);
  
  // TLD must be at least 2 characters
  if (tld.length < 2) return false;
  
  // TLD must consist of letters (Unicode supported) or start with xn--
  if (tld.startsWith('xn--')) {
    return /^[a-z0-9]+$/i.test(tld);
  } else {
    try {
      return /^\p{L}+$/u.test(tld);
    } catch (e) {
      return /^[a-z]+$/i.test(tld);
    }
  }
}

function Scanner() {
  const [domainInput, setDomainInput] = useState('');
  const [batchInput, setBatchInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [singleResult, setSingleResult] = useState(null);
  const [batchResults, setBatchResults] = useState([]);
  const [isBatchMode, setIsBatchMode] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // Active Learning states
  const [reportMsg, setReportMsg] = useState('');
  const [isReporting, setIsReporting] = useState(false);

  const handleSingleScan = async (e) => {
    e.preventDefault();
    const targetDomain = domainInput.trim();
    if (!targetDomain) return;

    if (!isValidUrlOrDomain(targetDomain)) {
      setErrorMsg('Please enter a valid URL or domain.');
      setSingleResult(null);
      return;
    }

    setIsScanning(true);
    setErrorMsg('');
    setSingleResult(null);
    setReportMsg('');
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

    const validDomains = domains.filter(isValidUrlOrDomain);
    if (validDomains.length === 0) {
      setErrorMsg('Please enter at least one valid URL or domain.');
      setBatchResults([]);
      return;
    }
    
    setIsScanning(true);
    setErrorMsg('');
    setBatchResults([]);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/predict/batch`, {
        domains: validDomains
      });
      setBatchResults(response.data.predictions);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.response?.data?.detail || 'Failed to run batch scans.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleReportMistake = async (domain, currentLabel) => {
    const correctedLabel = currentLabel === 'phishing' ? 'legitimate' : 'phishing';
    setIsReporting(true);
    setReportMsg('');
    try {
      const response = await axios.post(`${API_BASE_URL}/api/report`, {
        domain: domain,
        corrected_label: correctedLabel
      });
      setReportMsg(response.data.message);
    } catch (err) {
      console.error(err);
      setReportMsg(err.response?.data?.detail || 'Failed to report mistake.');
    } finally {
      setIsReporting(false);
    }
  };

  return (
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
                
                {/* Report Mistake Button */}
                <div style={{ marginTop: '1.5rem', width: '100%' }}>
                  <button 
                    className="tab-btn" 
                    onClick={() => handleReportMistake(singleResult.domain, singleResult.label)}
                    disabled={isReporting || reportMsg.includes('Successfully')}
                    style={{ width: '100%', borderRadius: '0.5rem', fontSize: '0.8rem', padding: '0.5rem', justifyContent: 'center', background: 'rgba(255,255,255,0.05)' }}
                  >
                    {isReporting ? 'Reporting...' : 
                     reportMsg.includes('Successfully') ? 'Reported!' :
                     `Flag as ${singleResult.label === 'phishing' ? 'Legitimate' : 'Phishing'}`}
                  </button>
                  {reportMsg && (
                    <p style={{ fontSize: '0.7rem', marginTop: '0.5rem', color: reportMsg.includes('Failed') ? 'var(--color-phish)' : 'var(--color-legit)' }}>
                      {reportMsg}
                    </p>
                  )}
                </div>
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
  );
}

export default Scanner;
