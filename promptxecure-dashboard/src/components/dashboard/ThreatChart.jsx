import React from 'react';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
} from 'recharts';

const COLORS = {
    blocked: '#ff3b5c',
    sanitized: '#ff9f43',
    passed: '#00ff88',
};

const PIE_COLORS = [
    '#ff3b5c', '#ff9f43', '#00ff88', '#00e5ff', '#a855f7', '#3b82f6',
];

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{
            background: 'var(--bg-secondary)', border: 'var(--glass-border)',
            borderRadius: 'var(--radius-sm)', padding: '10px 14px', fontSize: '0.82rem',
        }}>
            {label && <p style={{ color: 'var(--text-muted)', marginBottom: 6 }}>{label}</p>}
            {payload.map((p, i) => (
                <p key={i} style={{ color: p.color || p.fill, fontWeight: 600 }}>
                    {p.name}: {p.value}
                </p>
            ))}
        </div>
    );
};

/** Actions breakdown bar (blocked / sanitized / passed) */
export function ActionsChart({ stats }) {
    if (!stats) return null;

    const data = [
        { name: 'Blocked',   value: stats.blocked   || 0, fill: COLORS.blocked   },
        { name: 'Sanitized', value: stats.sanitized  || 0, fill: COLORS.sanitized },
        { name: 'Passed',    value: stats.passed     || 0, fill: COLORS.passed    },
    ].filter(d => d.value > 0);

    if (data.length === 0) {
        return (
            <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
                No scan data yet
            </div>
        );
    }

    return (
        <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data} barSize={48}>
                <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                    {data.map((entry, index) => (
                        <Cell key={index} fill={entry.fill} />
                    ))}
                </Bar>
            </BarChart>
        </ResponsiveContainer>
    );
}

/** Threat categories pie chart */
export function CategoriesPie({ categories }) {
    if (!categories?.length) {
        return (
            <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
                No threat categories yet
            </div>
        );
    }

    return (
        <ResponsiveContainer width="100%" height={220}>
            <PieChart>
                <Pie
                    data={categories}
                    dataKey="count"
                    nameKey="category"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    innerRadius={40}
                    paddingAngle={3}
                >
                    {categories.map((_, index) => (
                        <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                    wrapperStyle={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}
                    formatter={(value) => value.replace(/_/g, ' ')}
                />
            </PieChart>
        </ResponsiveContainer>
    );
}

/** Hourly scan trend line chart */
export function HourlyTrend({ trend }) {
    if (!trend?.length) {
        return (
            <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
                No hourly data yet
            </div>
        );
    }

    return (
        <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trend}>
                <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
                <XAxis dataKey="hour" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Line type="monotone" dataKey="total" stroke="var(--accent-cyan)" strokeWidth={2} dot={false} name="Total" />
                <Line type="monotone" dataKey="blocked" stroke="var(--accent-red)" strokeWidth={2} dot={false} name="Blocked" />
            </LineChart>
        </ResponsiveContainer>
    );
}
