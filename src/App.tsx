import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/layout/Navbar';
import { Footer } from './components/layout/Footer';
import { ToastContainer } from './components/ui/ToastContainer';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { AnalysisPage } from './pages/AnalysisPage';
import { ReportDetailPage } from './pages/ReportDetailPage';
import { ReportsPage } from './pages/ReportsPage';

export default function App() {
  return (
    <Router>
      <div id="apkguard-app-root" className="min-h-screen bg-[#050508] text-slate-100 flex flex-col font-sans selection:bg-sky-500/20 selection:text-white">
        {/* Global sticky cybersecurity navigation */}
        <Navbar />

        {/* Global notifications layer */}
        <ToastContainer />

        {/* Main Routed Page Content */}
        <main className="flex-1 flex flex-col">
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/analysis/:jobId" element={<AnalysisPage />} />
            <Route path="/report/:apkName" element={<ReportDetailPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>

        {/* CISO Dark Footer */}
        <Footer />
      </div>
    </Router>
  );
}
