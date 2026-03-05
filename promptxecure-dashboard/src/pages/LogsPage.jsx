import React, { useState, useEffect, useCallback } from 'react';
import LogsTable from '../components/logs/LogsTable';
import { getLogs } from '../utils/api';

const RISK_FILTERS = [
    { label: 'All', value: null },
    { label: 'Malicious', value: 'malicious' },
    { label: 'Suspicious', value: 'suspicious' },
    { label: 'Safe', value: 'safe' },
];

export default function LogsPage() {
    const [logs, setLogs] = useState([]);
    const [total, setTotal] = useState(0);
    const [totalPages, setTotalPages] = useState(1);
    const [page, setPage] = useState(1);
    const [perPage] = useState(20);
    const [riskFilter, setRiskFilter] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await getLogs(page, perPage, riskFilter);
            setLogs(data.logs || []);
            setTotal(data.total || 0);
            setTotalPages(data.total_pages || 1);
        } catch (err) {
            setError(err.message || 'Failed to load logs');
        } finally {
            setLoading(false);
        }
    }, [page, perPage, riskFilter]);

    useEffect(() => { load(); }, [load]);

    const handleFilterChange = (value) => {
        setRiskFilter(value);
        setPage(1);
    };

    return (
        <div>
            <h1 className="page-title">📋 Scan Logs</h1>
            <p className="page-subtitle">
                Full audit trail of every analyzed prompt with risk scores and threat details.
            </p>

            {/* Filters + controls */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                    {RISK_FILTERS.map(({ label, value }) => (
                        <button
                            key={label}
                            className="btn btn-ghost"
                            style={{
                                padding: '6px 14px', fontSize: '0.8rem',
                                background: riskFilter === value ? 'rgba(0,229,255,0.1)' : undefined,
                                color: riskFilter === value ? 'var(--accent-cyan)' : undefined,
                                borderColor: riskFilter === value ? 'var(--accent-cyan)' : undefined,
                            }}
                            onClick={() => handleFilterChange(value)}
                        >
                            {label}
                        </button>
                    ))}
                </div>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        {total.toLocaleString()} total scans
                    </span>
                    <button className="btn btn-ghost" onClick={load} style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
                        ↻ Refresh
                    </button>
                </div>
            </div>

            {/* Error */}
            {error && (
                <div style={{
                    padding: '14px 20px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(255,59,92,0.08)', border: '1px solid rgba(255,59,92,0.2)',
                    color: 'var(--accent-red)', marginBottom: 20, fontSize: '0.9rem',
                }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <LogsTable logs={logs} loading={loading} />
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 20, alignItems: 'center' }}>
                    <button
                        className="btn btn-ghost"
                        style={{ padding: '6px 14px' }}
                        onClick={() => setPage(p => Math.max(1, p - 1))}
                        disabled={page === 1}
                    >
                        ← Prev
                    </button>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', padding: '0 12px' }}>
                        Page {page} of {totalPages}
                    </span>
                    <button
                        className="btn btn-ghost"
                        style={{ padding: '6px 14px' }}
                        onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                        disabled={page === totalPages}
                    >
                        Next →
                    </button>
                </div>
            )}
        </div>
    );
}
