import React, { useState, useEffect, useCallback } from 'react';
import StatsGrid from '../components/dashboard/StatsGrid';
import { ActionsChart, CategoriesPie, HourlyTrend } from '../components/dashboard/ThreatChart';
import { getAnalytics } from '../utils/api';

const TIME_RANGES = [
    { label: '1h',   value: 1   },
    { label: '6h',   value: 6   },
    { label: '24h',  value: 24  },
    { label: '7d',   value: 168 },
    { label: '30d',  value: 720 },
];

export default function DashboardPage() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [hours, setHours] = useState(24);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await getAnalytics(hours);
            setStats(data);
        } catch (err) {
            setError(err.message || 'Failed to load analytics');
        } finally {
            setLoading(false);
        }
    }, [hours]);

    useEffect(() => { load(); }, [load]);

    // Auto-refresh every 30 seconds
    useEffect(() => {
        const id = setInterval(load, 30_000);
        return () => clearInterval(id);
    }, [load]);

    return (
        <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24, flexWrap: 'wrap', gap: 12 }}>
                <div>
                    <h1 className="page-title" style={{ marginBottom: 4 }}>📊 Analytics Dashboard</h1>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        Auto-refreshes every 30s · Live threat metrics
                    </p>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                    {TIME_RANGES.map(({ label, value }) => (
                        <button
                            key={value}
                            onClick={() => setHours(value)}
                            className="btn btn-ghost"
                            style={{
                                padding: '6px 14px', fontSize: '0.8rem',
                                background: hours === value ? 'rgba(0,229,255,0.1)' : undefined,
                                color: hours === value ? 'var(--accent-cyan)' : undefined,
                                borderColor: hours === value ? 'var(--accent-cyan)' : undefined,
                            }}
                        >
                            {label}
                        </button>
                    ))}
                    <button className="btn btn-ghost" onClick={load} style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
                        {loading ? '⟳' : '↻'} Refresh
                    </button>
                </div>
            </div>

            {error && (
                <div style={{
                    padding: '14px 20px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(255,59,92,0.08)', border: '1px solid rgba(255,59,92,0.2)',
                    color: 'var(--accent-red)', marginBottom: 24, fontSize: '0.9rem',
                }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Stats Grid */}
            <StatsGrid stats={stats} />

            {/* Charts row */}
            <div className="grid-2" style={{ marginBottom: 24 }}>
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Actions Breakdown</span>
                    </div>
                    {loading ? (
                        <div className="loading"><span className="spinner" />Loading…</div>
                    ) : (
                        <ActionsChart stats={stats} />
                    )}
                </div>

                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Threat Categories</span>
                    </div>
                    {loading ? (
                        <div className="loading"><span className="spinner" />Loading…</div>
                    ) : (
                        <CategoriesPie categories={stats?.top_categories} />
                    )}
                </div>
            </div>

            {/* Hourly Trend */}
            <div className="card" style={{ marginBottom: 24 }}>
                <div className="card-header">
                    <span className="card-title">Scan Volume Over Time</span>
                </div>
                {loading ? (
                    <div className="loading"><span className="spinner" />Loading…</div>
                ) : (
                    <HourlyTrend trend={stats?.hourly_trend} />
                )}
            </div>

            {/* OWASP alignment table */}
            <div className="card">
                <div className="card-header">
                    <span className="card-title">OWASP LLM Top 10 Coverage</span>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>OWASP Risk</th>
                                <th>PromptXecure Mitigation</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {[
                                { risk: 'LLM01: Prompt Injection', mitigation: '4-layer detection pipeline', status: 'active' },
                                { risk: 'LLM02: Insecure Output Handling', mitigation: 'Output Validator layer', status: 'active' },
                                { risk: 'LLM06: Sensitive Information Disclosure', mitigation: 'PII detection in outputs', status: 'active' },
                                { risk: 'LLM07: Insecure Plugin Design', mitigation: 'Input validation before tool use', status: 'active' },
                            ].map(({ risk, mitigation, status }) => (
                                <tr key={risk}>
                                    <td style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.85rem' }}>{risk}</td>
                                    <td style={{ fontSize: '0.85rem' }}>{mitigation}</td>
                                    <td>
                                        <span className="badge badge-safe">✓ {status}</span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
