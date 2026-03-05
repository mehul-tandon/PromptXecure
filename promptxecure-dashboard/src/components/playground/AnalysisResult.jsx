import React from 'react';
import ThreatCard from './ThreatCard';
import { fmtScore, riskBadgeClass, actionBadgeClass, riskColor, fmtMs } from '../../utils/helpers';

function ScoreArc({ score }) {
    const pct = Math.min(1, Math.max(0, score));
    const color = pct >= 0.7 ? 'var(--accent-red)' : pct >= 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)';
    const r = 70, cx = 90, cy = 90;
    const circumference = Math.PI * r; // half-circle
    const dashOffset = circumference * (1 - pct);

    return (
        <svg width="180" height="100" viewBox="0 0 180 100">
            {/* Track */}
            <path
                d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
                fill="none"
                stroke="rgba(255,255,255,0.06)"
                strokeWidth="12"
                strokeLinecap="round"
            />
            {/* Fill */}
            <path
                d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
                fill="none"
                stroke={color}
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray={`${circumference}`}
                strokeDashoffset={`${dashOffset}`}
                style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
            />
            <text x={cx} y={cy - 8} textAnchor="middle" fill={color} fontSize="22" fontWeight="800" fontFamily="Inter,sans-serif">
                {Math.round(pct * 100)}%
            </text>
            <text x={cx} y={cy + 10} textAnchor="middle" fill="var(--text-muted)" fontSize="10" fontFamily="Inter,sans-serif">
                RISK SCORE
            </text>
        </svg>
    );
}

function LayerRow({ name, layer }) {
    const triggered = layer?.triggered;
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '8px 12px', borderRadius: 'var(--radius-sm)',
            background: triggered ? 'rgba(255,59,92,0.05)' : 'rgba(0,0,0,0.2)',
            marginBottom: 6,
            border: `1px solid ${triggered ? 'rgba(255,59,92,0.15)' : 'rgba(255,255,255,0.04)'}`,
        }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, textTransform: 'capitalize' }}>
                {name.replace(/_/g, ' ')}
            </span>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                    color: layer?.score >= 0.7 ? 'var(--accent-red)' : layer?.score >= 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)',
                }}>
                    {fmtScore(layer?.score)}
                </span>
                <span style={{
                    fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: 100,
                    background: triggered ? 'rgba(255,59,92,0.15)' : 'rgba(0,255,136,0.1)',
                    color: triggered ? 'var(--accent-red)' : 'var(--accent-green)',
                }}>
                    {triggered ? 'TRIGGERED' : 'CLEAR'}
                </span>
            </div>
        </div>
    );
}

export default function AnalysisResult({ result }) {
    if (!result) return null;

    const { status, original_prompt, sanitized_prompt, llm_response, analysis } = result;
    const { risk_score, risk_level, threats_detected = [], layers = {} } = analysis || {};

    return (
        <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Verdict Banner */}
            <div style={{
                padding: '16px 24px',
                borderRadius: 'var(--radius-md)',
                background: status === 'blocked' ? 'rgba(255,59,92,0.08)' : status === 'sanitized' ? 'rgba(255,159,67,0.08)' : 'rgba(0,255,136,0.08)',
                border: `1px solid ${riskColor(risk_level)}33`,
                display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap',
            }}>
                <span style={{ fontSize: '2rem' }}>
                    {status === 'blocked' ? '🚫' : status === 'sanitized' ? '🔧' : '✅'}
                </span>
                <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: riskColor(risk_level) }}>
                        {status === 'blocked' ? 'BLOCKED' : status === 'sanitized' ? 'SANITIZED & FORWARDED' : 'PASSED — SAFE'}
                    </div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                        Risk Level: <span className={riskBadgeClass(risk_level)}>{risk_level?.toUpperCase()}</span>
                        &nbsp;·&nbsp;
                        Action: <span className={actionBadgeClass(status)}>{status?.toUpperCase()}</span>
                    </div>
                </div>
                <ScoreArc score={risk_score} />
            </div>

            {/* Detection Layers */}
            <div className="card">
                <div className="card-header">
                    <span className="card-title">Detection Layers</span>
                </div>
                {Object.entries(layers).map(([name, layer]) => (
                    <LayerRow key={name} name={name} layer={layer} />
                ))}
                {Object.keys(layers).length === 0 && (
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No layer data.</p>
                )}
            </div>

            {/* Threats */}
            {threats_detected.length > 0 && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">⚡ Threats Detected ({threats_detected.length})</span>
                    </div>
                    {threats_detected.map((t, i) => (
                        <ThreatCard key={i} threat={t} />
                    ))}
                </div>
            )}

            {/* Sanitized Prompt */}
            {sanitized_prompt && sanitized_prompt !== original_prompt && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">🔧 Sanitized Prompt</span>
                    </div>
                    <pre style={{
                        background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 'var(--radius-sm)',
                        fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--accent-orange)',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0,
                    }}>
                        {sanitized_prompt}
                    </pre>
                </div>
            )}

            {/* LLM Response */}
            {llm_response && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">🤖 LLM Response</span>
                    </div>
                    <div style={{
                        background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 'var(--radius-sm)',
                        fontSize: '0.9rem', lineHeight: 1.7, color: 'var(--text-primary)',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    }}>
                        {llm_response}
                    </div>
                </div>
            )}
        </div>
    );
}
