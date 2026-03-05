import React, { useState } from 'react';
import PromptInput from '../components/playground/PromptInput';
import AnalysisResult from '../components/playground/AnalysisResult';
import { playground as callPlayground } from '../utils/api';

export default function PlaygroundPage() {
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleSubmit = async (prompt, model, sendToLlm) => {
        setLoading(true);
        setError(null);
        setResult(null);
        try {
            const data = await callPlayground(prompt, model, sendToLlm);
            setResult(data);
        } catch (err) {
            setError(err.message || 'Failed to connect to the API. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ maxWidth: 900, margin: '0 auto' }}>
            <h1 className="page-title">🧪 Prompt Injection Playground</h1>
            <p className="page-subtitle">
                Test prompts against the 4-layer detection pipeline in real time.
                Try the attack examples to see how PromptXecure detects and contains threats.
            </p>

            {/* Input Card */}
            <div className="card" style={{ marginBottom: 24 }}>
                <PromptInput onSubmit={handleSubmit} loading={loading} />
            </div>

            {/* Error */}
            {error && (
                <div style={{
                    padding: '14px 20px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(255,59,92,0.08)', border: '1px solid rgba(255,59,92,0.2)',
                    color: 'var(--accent-red)', marginBottom: 24, fontSize: '0.9rem',
                }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Spinner while loading */}
            {loading && !result && (
                <div className="loading">
                    <span className="spinner" />
                    Running detection pipeline…
                </div>
            )}

            {/* Result */}
            {result && <AnalysisResult result={result} />}

            {/* How it works */}
            {!result && !loading && !error && (
                <div className="card" style={{ background: 'rgba(0,0,0,0.2)' }}>
                    <h3 style={{ fontSize: '0.95rem', marginBottom: 16, color: 'var(--text-secondary)' }}>
                        How the Detection Pipeline Works
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
                        {[
                            { icon: '🔡', layer: 'Layer 1: Preprocessor', desc: 'Unicode normalization, Base64/Hex/URL decoding, HTML stripping' },
                            { icon: '📋', layer: 'Layer 2: Rule Engine', desc: '100+ YAML attack signatures — jailbreaks, injections, PII' },
                            { icon: '🧠', layer: 'Layer 3: ML Classifier', desc: 'Sentence-Transformer embeddings + XGBoost semantic analysis' },
                            { icon: '👁️', layer: 'Layer 4: Shadow LLM', desc: 'Secondary LLM meta-prompt safety reviewer (when enabled)' },
                        ].map(({ icon, layer, desc }) => (
                            <div key={layer} style={{
                                padding: '14px 16px', borderRadius: 'var(--radius-sm)',
                                background: 'rgba(0,229,255,0.03)', border: 'var(--glass-border)',
                            }}>
                                <div style={{ fontSize: '1.5rem', marginBottom: 8 }}>{icon}</div>
                                <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: 4 }}>
                                    {layer}
                                </div>
                                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                                    {desc}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
