import React from 'react';
import { categoryIcon } from '../../utils/helpers';

const SEVERITY_COLOR = (s) => {
    if (s >= 0.8) return 'var(--accent-red)';
    if (s >= 0.5) return 'var(--accent-orange)';
    return 'var(--accent-cyan)';
};

export default function ThreatCard({ threat }) {
    const { type, layer, confidence, description, pattern_matched, severity } = threat;
    return (
        <div className="threat-card">
            <span className="threat-icon">{categoryIcon(type)}</span>
            <div className="threat-info">
                <h4>{type?.replace(/_/g, ' ').toUpperCase()}</h4>
                <p>{description}</p>
                {pattern_matched && (
                    <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent-orange)', marginTop: 4 }}>
                        Match: "{pattern_matched}"
                    </p>
                )}
                <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>
                    Layer: {layer}
                </p>
            </div>
            <span className="threat-score" style={{ color: SEVERITY_COLOR(severity) }}>
                {Math.round((confidence || severity || 0) * 100)}%
            </span>
        </div>
    );
}
