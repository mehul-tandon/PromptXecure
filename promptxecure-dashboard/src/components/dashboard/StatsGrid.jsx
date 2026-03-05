import React from 'react';

function StatCard({ label, value, accent, icon, sub }) {
    return (
        <div className={`card stat-card ${accent || ''}`}>
            <div className="card-header" style={{ marginBottom: 0 }}>
                <span className="card-title">{label}</span>
                <span style={{ fontSize: '1.4rem' }}>{icon}</span>
            </div>
            <div className="stat-value">{value}</div>
            {sub && <div className="stat-label">{sub}</div>}
        </div>
    );
}

export default function StatsGrid({ stats }) {
    if (!stats) {
        return (
            <div className="stats-grid">
                {[1, 2, 3, 4].map(i => (
                    <div key={i} className="card" style={{ height: 110, background: 'rgba(255,255,255,0.02)' }} />
                ))}
            </div>
        );
    }

    const blockRate = stats.block_rate != null ? `${(stats.block_rate * 100).toFixed(1)}%` : '—';

    return (
        <div className="stats-grid">
            <StatCard
                label="Total Scans"
                value={(stats.total_scans || 0).toLocaleString()}
                accent="cyan"
                icon="🔍"
                sub="prompts analyzed"
            />
            <StatCard
                label="Blocked"
                value={(stats.blocked || 0).toLocaleString()}
                accent="red"
                icon="🚫"
                sub={`Block rate: ${blockRate}`}
            />
            <StatCard
                label="Sanitized"
                value={(stats.sanitized || 0).toLocaleString()}
                accent="orange"
                icon="🔧"
                sub="attacks stripped"
            />
            <StatCard
                label="Avg Risk Score"
                value={`${Math.round((stats.avg_risk_score || 0) * 100)}%`}
                accent={stats.avg_risk_score >= 0.7 ? 'red' : stats.avg_risk_score >= 0.3 ? 'orange' : 'green'}
                icon="📊"
                sub={`Avg latency: ${Math.round(stats.avg_latency_ms || 0)}ms`}
            />
        </div>
    );
}
