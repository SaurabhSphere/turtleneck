import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Routes, Route } from 'react-router-dom';
import { 
  ShieldAlert, 
  Activity, 
  History, 
  Globe
} from 'lucide-react';

import Scanner from './components/Scanner';
import Stats from './components/Stats';
import Logs from './components/Logs';
import NotFound from './components/NotFound';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://turtleneck-m5bc.onrender.com';

function Dashboard() {
  const [activeTab, setActiveTab] = useState('scanner');

  // Wake-up ping to backend
  useEffect(() => {
    axios.get(`${API_BASE_URL}/`).catch(() => {
      // Ignore errors, we just want to ping
    });
  }, []);

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
        {activeTab === 'scanner' && <Scanner />}
        {activeTab === 'stats' && <Stats />}
        {activeTab === 'history' && <Logs />}
      </main>
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
