/**
 * PromptXecure Dashboard — API Client
 * All communication with the FastAPI backend.
 */

const BASE_URL = import.meta.env.VITE_API_URL || '';

async function request(path, options = {}) {
    const url = `${BASE_URL}${path}`;
    const res = await fetch(url, {
        headers: {
            'Content-Type': 'application/json',
            ...(options.headers || {}),
        },
        ...options,
    });

    if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try {
            const body = await res.json();
            detail = body.detail || body.error || detail;
        } catch (_) {}
        throw new Error(detail);
    }

    return res.json();
}

/** POST /api/v1/playground */
export async function playground(prompt, model = 'gpt-4o-mini', sendToLlm = true) {
    return request('/api/v1/playground', {
        method: 'POST',
        body: JSON.stringify({ prompt, model, send_to_llm: sendToLlm }),
    });
}

/** POST /api/v1/detect */
export async function detect(prompt) {
    return request('/api/v1/detect', {
        method: 'POST',
        body: JSON.stringify({ prompt }),
    });
}

/** POST /api/v1/sanitize */
export async function sanitize(prompt) {
    return request('/api/v1/sanitize', {
        method: 'POST',
        body: JSON.stringify({ prompt }),
    });
}

/** POST /api/v1/analyze */
export async function analyze(prompt, model = 'gpt-4o-mini') {
    return request('/api/v1/analyze', {
        method: 'POST',
        body: JSON.stringify({ prompt, model }),
    });
}

/** GET /api/v1/analytics */
export async function getAnalytics(hours = 24) {
    return request(`/api/v1/analytics?hours=${hours}`);
}

/** GET /api/v1/logs */
export async function getLogs(page = 1, perPage = 20, riskLevel = null) {
    const params = new URLSearchParams({ page, per_page: perPage });
    if (riskLevel) params.set('risk_level', riskLevel);
    return request(`/api/v1/logs?${params}`);
}

/** GET /api/v1/health */
export async function getHealth() {
    return request('/api/v1/health');
}
