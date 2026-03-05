import React from 'react';
import { NavLink } from 'react-router-dom';

const NAV_ITEMS = [
    { to: '/playground', icon: '🧪', label: 'Playground' },
    { to: '/dashboard', icon: '📊', label: 'Dashboard' },
    { to: '/logs',      icon: '📋', label: 'Logs'       },
];

export default function Sidebar() {
    return (
        <aside className="sidebar">
            <div className="sidebar-logo">
                <div className="logo-icon">🔐</div>
                <h1>PromptXecure</h1>
            </div>

            <nav className="sidebar-nav">
                {NAV_ITEMS.map(({ to, icon, label }) => (
                    <NavLink
                        key={to}
                        to={to}
                        className={({ isActive }) =>
                            `nav-link${isActive ? ' active' : ''}`
                        }
                    >
                        <span className="nav-icon">{icon}</span>
                        <span>{label}</span>
                    </NavLink>
                ))}
            </nav>

            <div className="sidebar-footer">
                <div style={{ color: 'var(--accent-green)', fontSize: '0.7rem', fontWeight: 600, marginBottom: 4 }}>
                    ● OWASP LLM01:2025
                </div>
                <div>Zero-Trust AI Firewall</div>
                <div style={{ marginTop: 4 }}>v0.1.0</div>
            </div>
        </aside>
    );
}
