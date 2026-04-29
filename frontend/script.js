/**
 * Healthcare Security Platform - Shared JavaScript Utilities
 * Fixes: relative API_BASE, correct redirect paths, robust error handling
 */

// ── Relative API base — works on any host/port ───────────────────────────────
const API_BASE = '/api';

// ── Token Management ─────────────────────────────────────────────────────────
const Auth = {
  setToken(token)  { localStorage.setItem('hcs_token', token); },
  getToken()       { return localStorage.getItem('hcs_token'); },
  setUser(user)    { localStorage.setItem('hcs_user', JSON.stringify(user)); },
  getUser()        {
    try {
      const u = localStorage.getItem('hcs_user');
      return u ? JSON.parse(u) : null;
    } catch(e) { return null; }
  },
  clear()          {
    localStorage.removeItem('hcs_token');
    localStorage.removeItem('hcs_user');
  },
  isLoggedIn()     { return !!this.getToken(); },
  getRole()        { const u = this.getUser(); return u ? u.role : null; },

  requireLogin(role = null) {
    if (!this.isLoggedIn()) {
      window.location.replace('/login.html');
      return false;
    }
    if (role && this.getRole() !== role) {
      this.redirectToDashboard();
      return false;
    }
    return true;
  },

  redirectToDashboard() {
    const role = this.getRole();
    const map = {
      admin:   '/admin_dashboard.html',
      doctor:  '/doctor_dashboard.html',
      patient: '/patient_dashboard.html'
    };
    const dest = map[role] || '/login.html';
    window.location.replace(dest);
  },

  logout() {
    this.clear();
    window.location.replace('/login.html');
  }
};

// ── HTTP Client ───────────────────────────────────────────────────────────────
const Http = {
  async request(method, endpoint, body = null, auth = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) {
      const token = Auth.getToken();
      if (token) headers['Authorization'] = 'Bearer ' + token;
    }
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    try {
      const res = await fetch(API_BASE + endpoint, opts);
      let data = {};
      try { data = await res.json(); } catch(e) { data = { error: 'Invalid server response' }; }
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      console.error('HTTP error:', err);
      return { ok: false, status: 0, data: { error: 'Network error — is the server running?' } };
    }
  },
  get(endpoint, auth = true)        { return this.request('GET',    endpoint, null, auth); },
  post(endpoint, body, auth = true) { return this.request('POST',   endpoint, body, auth); },
  delete(endpoint, auth = true)     { return this.request('DELETE', endpoint, null, auth); },
};

// ── Toast Notifications ───────────────────────────────────────────────────────
const Toast = {
  container: null,
  init() {
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    }
  },
  show(message, type = 'info', duration = 3500) {
    this.init();
    const icons = { success: '✓', error: '✕', info: 'ℹ', warning: '⚠' };
    const toast = document.createElement('div');
    toast.className = 'toast ' + (type === 'error' ? 'error' : type === 'success' ? 'success' : 'info');
    toast.innerHTML = '<span style="font-weight:700">' + (icons[type]||'ℹ') + '</span> ' + message;
    this.container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => { if (toast.parentNode) toast.remove(); }, 250);
    }, duration);
  }
};

// ── DOM Helpers ───────────────────────────────────────────────────────────────
const UI = {
  show(selector)         { const el = document.querySelector(selector); if (el) el.style.display = ''; },
  hide(selector)         { const el = document.querySelector(selector); if (el) el.style.display = 'none'; },
  setHtml(selector, html){ const el = document.querySelector(selector); if (el) el.innerHTML = html; },
  setText(selector, text){ const el = document.querySelector(selector); if (el) el.textContent = text; },
  showSection(id) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    const el = document.getElementById(id);
    if (el) el.classList.add('active');
  },
  loading(btnEl, state) {
    if (!btnEl) return;
    if (state) {
      btnEl.dataset.original = btnEl.innerHTML;
      btnEl.innerHTML = '<span class="spinner"></span> Please wait...';
      btnEl.disabled = true;
    } else {
      btnEl.innerHTML = btnEl.dataset.original || btnEl.innerHTML;
      btnEl.disabled = false;
    }
  },
  formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
    } catch(e) { return iso; }
  },
  badge(text, type) {
    return '<span class="badge badge-' + type + '">' + text + '</span>';
  }
};

// ── Report Type Helpers (kept for doctor dashboard compatibility) ──────────────
const ReportTypes = {
  vital_signs:  { label: 'Vital Signs',  fields: [] },
  blood_test:   { label: 'Blood Test',   fields: [] },
  urine_test:   { label: 'Urine Test',   fields: [] },
  imaging:      { label: 'Imaging',      fields: [] },
  ecg:          { label: 'ECG',          fields: [] },
  prescription: { label: 'Prescription', fields: [] },
  vaccination:  { label: 'Vaccination',  fields: [] },
  surgery:      { label: 'Surgery',      fields: [] },
  allergy:      { label: 'Allergy Test', fields: [] },
  diabetes:     { label: 'Diabetes',     fields: [] },
  thyroid:      { label: 'Thyroid',      fields: [] },
  other:        { label: 'Other',        fields: [] }
};

function renderReportData(data, reportType) {
  if (!data || typeof data !== 'object') return '<div class="crypto-info"><span style="color:var(--text-muted)">No data</span></div>';
  const rows = Object.entries(data).map(([k, v]) => {
    if (v === '' || v === null || v === undefined) return '';
    if (typeof v === 'object') {
      // nested object like { parameters: { Bilirubin: '0.8' } }
      return Object.entries(v).map(([k2, v2]) =>
        v2 ? '<div><span class="label">' + k2.replace(/_/g,' ') + ':</span> <span class="value">' + v2 + '</span></div>' : ''
      ).join('');
    }
    return '<div><span class="label">' + k.replace(/_/g,' ') + ':</span> <span class="value">' + v + '</span></div>';
  }).filter(Boolean).join('');
  return '<div class="crypto-info">' + (rows || '<span style="color:var(--text-muted)">No fields recorded</span>') + '</div>';
}
