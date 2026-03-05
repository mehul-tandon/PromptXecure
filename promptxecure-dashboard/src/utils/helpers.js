/** Format a risk score (0–1) as a percentage string. */
export function fmtScore(score) {
    return `${Math.round((score || 0) * 100)}%`;
}

/** Map a risk level string to a CSS class. */
export function riskClass(level) {
    if (!level) return 'safe';
    return level.toLowerCase();
}

/** Map an action string to a CSS badge class. */
export function actionBadgeClass(action) {
    const map = { blocked: 'badge-blocked', sanitized: 'badge-sanitized', passed: 'badge-passed' };
    return `badge ${map[action] || 'badge-passed'}`;
}

/** Map a risk level to a badge class. */
export function riskBadgeClass(level) {
    const map = { malicious: 'badge-malicious', suspicious: 'badge-suspicious', safe: 'badge-safe' };
    return `badge ${map[level] || 'badge-safe'}`;
}

/** Get the color variable name associated with a risk level. */
export function riskColor(level) {
    const map = {
        malicious: 'var(--accent-red)',
        suspicious: 'var(--accent-orange)',
        safe: 'var(--accent-green)',
    };
    return map[level] || 'var(--text-muted)';
}

/** Format ISO timestamp to readable local string. */
export function fmtDate(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
}

/** Truncate a string with ellipsis. */
export function truncate(str, max = 80) {
    if (!str || str.length <= max) return str || '';
    return str.slice(0, max) + '…';
}

/** Format milliseconds nicely. */
export function fmtMs(ms) {
    if (ms == null) return '—';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
}

/** Return emoji icon for attack category. */
export function categoryIcon(category) {
    const icons = {
        direct_injection: '💉',
        jailbreak: '🔓',
        data_extraction: '📤',
        delimiter_injection: '🔣',
        authority_override: '👑',
        obfuscation: '🕵️',
        multi_turn: '🔄',
        indirect_injection: '🌐',
        pii_leakage: '🔒',
        persona_switch: '🎭',
        restriction_bypass: '🚧',
        suspicious: '⚠️',
        heuristic_detection: '🔍',
    };
    return icons[category] || '⚡';
}
