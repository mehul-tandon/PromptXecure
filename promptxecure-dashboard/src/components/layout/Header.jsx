import React from 'react';
import { useLocation } from 'react-router-dom';

const PAGE_TITLES = {
    '/playground': 'Playground',
    '/':           'Playground',
    '/dashboard':  'Analytics Dashboard',
    '/logs':       'Scan Logs',
};

export default function Header() {
    const { pathname } = useLocation();
    const title = PAGE_TITLES[pathname] || 'PromptXecure';

    return (
        <header className="header">
            <span className="header-title">{title}</span>
            <div className="header-actions">
                <span
                    style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 6,
                        fontSize: '0.8rem',
                        color: 'var(--accent-green)',
                        fontWeight: 600,
                    }}
                >
                    <span style={{ width: 8, height: 8, background: 'var(--accent-green)', borderRadius: '50%', display: 'inline-block' }} />
                    API Connected
                </span>
            </div>
        </header>
    );
}
