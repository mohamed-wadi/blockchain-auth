/**
 * main.js — Login flow orchestrator (shared utilities)
 * Handles: BACKEND URL resolution, token storage helpers, auth guard.
 */

// ─── Backend URL ─────────────────────────────────────
const BACKEND = (() => {
    const h = window.location.hostname;
    if (h === 'localhost' || h === '127.0.0.1') return 'http://localhost:5000';
    // Replace with your Heroku app URL after deployment
    return 'https://wadi1111-blockchain-auth-backend.hf.space';
})();

// ─── Token helpers ────────────────────────────────────
const Auth = {
    getToken: () => localStorage.getItem('bca_token'),
    getUser: () => localStorage.getItem('bca_user'),
    setToken: (t, u) => { localStorage.setItem('bca_token', t); localStorage.setItem('bca_user', u); },
    clear: () => { localStorage.removeItem('bca_token'); localStorage.removeItem('bca_user'); },
    isLoggedIn: () => !!localStorage.getItem('bca_token'),
    guard: () => {
        if (!localStorage.getItem('bca_token')) window.location.href = '/index.html';
    },
};

// ─── API helper ───────────────────────────────────────
async function apiFetch(path, options = {}) {
    const defaults = {
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
    };
    const token = Auth.getToken();
    if (token) defaults.headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${BACKEND}${path}`, {
        ...defaults, ...options,
        headers: { ...defaults.headers, ...(options.headers || {}) }
    });
    return res;
}

// ─── UI helpers ───────────────────────────────────────
function showAlert(elementId, msg, type = 'error') {
    const el = document.getElementById(elementId);
    if (!el) return;
    const icons = { error: '⚠️', success: '✅', info: 'ℹ️', warn: '⚠️' };
    el.className = `alert alert-${type} show`;
    el.innerHTML = `<span>${icons[type] || '•'}</span><span>${msg}</span>`;
}

function hideAlert(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.className = 'alert';
}

function setLoading(btnId, on) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.classList.toggle('loading', on);
    btn.disabled = on;
}

// ─── Format helpers ───────────────────────────────────
function timeAgo(ts) {
    const diff = Date.now() / 1000 - ts;
    if (diff < 60) return `${Math.round(diff)}s`;
    if (diff < 3600) return `${Math.round(diff / 60)}m`;
    return `${Math.round(diff / 3600)}h`;
}

function shortHash(h, len = 12) {
    return h ? h.slice(0, len) + '…' : '—';
}
