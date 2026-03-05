import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';
import PlaygroundPage from './pages/PlaygroundPage';
import DashboardPage from './pages/DashboardPage';
import LogsPage from './pages/LogsPage';
import ErrorBoundary from './components/layout/ErrorBoundary';

export default function App() {
    return (
        <ErrorBoundary>
            <div className="app-layout">
                <Sidebar />
                <Header />
                <main className="main-content">
                    <Routes>
                        <Route path="/" element={<PlaygroundPage />} />
                        <Route path="/playground" element={<PlaygroundPage />} />
                        <Route path="/dashboard" element={<DashboardPage />} />
                        <Route path="/logs" element={<LogsPage />} />
                    </Routes>
                </main>
            </div>
        </ErrorBoundary>
    );
}
