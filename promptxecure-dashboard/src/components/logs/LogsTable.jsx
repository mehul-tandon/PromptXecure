import React from 'react';
import { fmtDate, fmtMs, riskBadgeClass, actionBadgeClass, truncate } from '../../utils/helpers';

export default function LogsTable({ logs, loading }) {
    if (loading) {
        return (
            <div className="loading">
                <span className="spinner" />
                Loading logs…
            </div>
        );
    }

    if (!logs?.length) {
        return (
            <div style={{
                textAlign: 'center', padding: '48px 0',
                color: 'var(--text-muted)', fontSize: '0.9rem',
            }}>
                <div style={{ fontSize: '3rem', marginBottom: 12 }}>📭</div>
                No scan logs found.
            </div>
        );
    }

    return (
        <div className="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Prompt Preview</th>
                        <th>Risk Score</th>
                        <th>Level</th>
                        <th>Action</th>
                        <th>Model</th>
                        <th>Latency</th>
                        <th>Threats</th>
                    </tr>
                </thead>
                <tbody>
                    {logs.map((log) => (
                        <tr key={log.id}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                                {fmtDate(log.timestamp)}
                            </td>
                            <td style={{ maxWidth: 260, color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                                {truncate(log.prompt_preview, 70)}
                            </td>
                            <td>
                                <span style={{
                                    fontFamily: 'var(--font-mono)',
                                    color: log.risk_score >= 0.7 ? 'var(--accent-red)' : log.risk_score >= 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)',
                                    fontWeight: 700,
                                }}>
                                    {Math.round((log.risk_score || 0) * 100)}%
                                </span>
                            </td>
                            <td>
                                <span className={riskBadgeClass(log.risk_level)}>
                                    {log.risk_level}
                                </span>
                            </td>
                            <td>
                                <span className={actionBadgeClass(log.action)}>
                                    {log.action}
                                </span>
                            </td>
                            <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                                {log.model_used || '—'}
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                                {fmtMs(log.processing_ms)}
                            </td>
                            <td>
                                {log.threats_count > 0 ? (
                                    <span style={{
                                        background: 'rgba(255,59,92,0.1)', color: 'var(--accent-red)',
                                        padding: '2px 8px', borderRadius: 100, fontSize: '0.75rem', fontWeight: 700,
                                    }}>
                                        {log.threats_count}
                                    </span>
                                ) : (
                                    <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>0</span>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
