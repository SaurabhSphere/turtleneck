import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';

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

export default NotFound;
