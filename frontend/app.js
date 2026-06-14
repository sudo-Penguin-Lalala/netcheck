/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 *
 * NetCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NetCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with NetCheck. If not, see <https://www.gnu.org/licenses/>.
 */

/* NetCheck frontend — vanilla, no framework, no build step.
 * Mounts: tabs, forms, IP card, history (localStorage), shortcuts, theme,
 *         shareable-URL params, toast notifications.
 */

const LS_KEYS = {
  history: 'nc.history.v1',
  theme: 'nc.theme.v1',
  tab: 'nc.tab.v1',
};
const HISTORY_MAX = 10;
const TAB_KEY_MAP = {
  d: 'dns', p: 'ping', t: 'traceroute', m: 'mtr',
  o: 'port', r: 'rdns', w: 'whois',
  h: 'headers', s: 'ssl', x: 'http',
};

/* ---------------- theme ---------------- */

const html = document.documentElement;
const themeBtn = document.getElementById('theme-toggle');

function applyTheme(theme) {
  html.dataset.theme = theme;
  themeBtn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
  themeBtn.setAttribute(
    'aria-label',
    theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme',
  );
  const icon = themeBtn.querySelector('[data-theme-icon]');
  if (icon) icon.textContent = theme === 'light' ? '☀' : '☾';
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => {
    if (!m.hasAttribute('media')) m.content = theme === 'light' ? '#f7f5f0' : '#0a0e14';
  });
}

(function initTheme() {
  const stored = localStorage.getItem(LS_KEYS.theme);
  if (stored === 'light' || stored === 'dark') {
    applyTheme(stored);
  } else {
    const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    applyTheme(prefersLight ? 'light' : 'dark');
  }
})();

themeBtn.addEventListener('click', () => {
  const next = html.dataset.theme === 'light' ? 'dark' : 'light';
  applyTheme(next);
  localStorage.setItem(LS_KEYS.theme, next);
});

/* ---------------- toast ---------------- */

const toastEl = document.getElementById('toast');
let toastTimer;
function showToast(msg) {
  if (!toastEl) return;
  toastEl.textContent = msg;
  toastEl.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastEl.hidden = true; }, 2000);
}

/* ---------------- tabs ---------------- */

const tabs = [...document.querySelectorAll('[role="tab"]')];
const panels = [...document.querySelectorAll('[role="tabpanel"]')];

function selectTab(tool, { focus = false } = {}) {
  tabs.forEach((t) => {
    const active = t.dataset.tool === tool;
    t.setAttribute('aria-selected', active ? 'true' : 'false');
    t.tabIndex = active ? 0 : -1;
    if (active && focus) t.focus();
  });
  panels.forEach((p) => {
    const active = p.id === `panel-${tool}`;
    p.hidden = !active;
  });
  localStorage.setItem(LS_KEYS.tab, tool);

  if (focus) {
    const next = document.querySelector(`#panel-${tool} input, #panel-${tool} select`);
    if (next) next.focus();
  }
}

tabs.forEach((t) => {
  t.addEventListener('click', () => selectTab(t.dataset.tool));
  t.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const dir = e.key === 'ArrowRight' ? 1 : -1;
      const idx = tabs.indexOf(t);
      const next = tabs[(idx + dir + tabs.length) % tabs.length];
      selectTab(next.dataset.tool, { focus: true });
    } else if (e.key === 'Home') {
      e.preventDefault();
      selectTab(tabs[0].dataset.tool, { focus: true });
    } else if (e.key === 'End') {
      e.preventDefault();
      selectTab(tabs[tabs.length - 1].dataset.tool, { focus: true });
    }
  });
});

(function initTab() {
  const stored = localStorage.getItem(LS_KEYS.tab);
  if (stored && tabs.some((t) => t.dataset.tool === stored)) selectTab(stored);
})();

/* ---------------- API client ---------------- */

async function api(path, options = {}) {
  const opts = {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    ...options,
  };
  const resp = await fetch(path, opts);
  let body = null;
  try { body = await resp.json(); } catch { /* non-json */ }
  if (!resp.ok) {
    const err = (body && body.message) || resp.statusText || 'Request failed';
    const e = new Error(err);
    e.status = resp.status;
    e.code = (body && body.error) || 'error';
    e.body = body;
    throw e;
  }
  return body;
}

/* ---------------- result rendering ---------------- */

const resultSection = document.querySelector('[data-result-section]');
const resultTitle = document.querySelector('[data-result-title]');
const resultBody = document.querySelector('[data-result-body]');
let lastResultText = '';
let loadingTimer = null;

function showResult(title, htmlContent) {
  clearInterval(loadingTimer);
  resultSection.hidden = false;
  resultTitle.textContent = `> ${title}`;
  resultBody.innerHTML = '';
  if (typeof htmlContent === 'string') {
    resultBody.innerHTML = htmlContent;
  } else {
    resultBody.appendChild(htmlContent);
  }
  lastResultText = resultBody.innerText;
  resultSection.setAttribute('aria-busy', 'false');
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showLoading(title) {
  clearInterval(loadingTimer);
  resultSection.hidden = false;
  resultTitle.textContent = `> ${title}`;
  resultBody.replaceChildren();
  const p = document.createElement('p');
  p.className = 'loading';
  const sp = document.createElement('span');
  sp.className = 'spinner spinner-lg';
  sp.setAttribute('aria-hidden', 'true');
  const lbl = document.createElement('span');
  lbl.className = 'label';
  lbl.textContent = 'running probe…';
  const el = document.createElement('span');
  el.className = 'dim';
  el.setAttribute('data-elapsed', '');
  el.textContent = '0.0s';
  p.append(sp, lbl, el);
  resultBody.appendChild(p);
  resultSection.setAttribute('aria-busy', 'true');
  lastResultText = '';
  const start = performance.now();
  loadingTimer = setInterval(() => {
    if (!el.isConnected) { clearInterval(loadingTimer); return; }
    el.textContent = `${((performance.now() - start) / 1000).toFixed(1)}s`;
  }, 100);
}

function showError(title, err) {
  clearInterval(loadingTimer);
  resultSection.hidden = false;
  resultTitle.textContent = `> ${title}`;
  const code = err.code || 'error';
  const msg = escapeHtml(err.message || 'Request failed');
  resultBody.innerHTML = `<div class="err"><strong>${escapeHtml(code)}</strong><br>${msg}</div>`;
  resultSection.setAttribute('aria-busy', 'false');
  lastResultText = resultBody.innerText;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/* ---------------- per-tool runners ---------------- */

const runners = {
  async dns({ host, type }) {
    const data = await api('/api/dns', { method: 'POST', body: JSON.stringify({ host, type }) });
    const rows = data.records.map((r) => `<tr><td class="nowrap">${escapeHtml(r)}</td></tr>`).join('');
    const html =
      `<p class="label">${escapeHtml(type)} records for ${escapeHtml(host)}` +
      ` <span class="dim">· ttl ${data.ttl}s · resolver ${escapeHtml(data.resolver)}</span></p>` +
      `<table aria-label="DNS records">${rows}</table>`;
    return { html, summary: `${data.records.length} ${type} record(s)` };
  },

  async ping({ host, count, location }) {
    const data = await api('/api/ping', { method: 'POST', body: JSON.stringify({ host, count: Number(count), location: location || undefined }) });
    const loss = `${data.loss_pct.toFixed(1)}%`;
    const lossClass = data.loss_pct === 0 ? 'ok' : data.loss_pct >= 50 ? 'err' : 'warn';
    const html =
      `<p class="label">ping ${escapeHtml(host)}</p>` +
      `<table aria-label="Ping summary">` +
      `<tr><th>sent</th><td>${data.packets_sent}</td>` +
      `    <th>received</th><td>${data.packets_recv}</td>` +
      `    <th>loss</th><td class="${lossClass}">${loss}</td></tr>` +
      `<tr><th>min</th><td>${data.min} ms</td>` +
      `    <th>avg</th><td>${data.avg} ms</td>` +
      `    <th>max</th><td>${data.max} ms</td></tr>` +
      `</table>` +
      `<details><summary class="label">raw output</summary><pre>${escapeHtml(data.raw)}</pre></details>`;
    return { html, summary: `${data.packets_recv}/${data.packets_sent} · ${data.avg}ms` };
  },

  async traceroute({ host, max_hops, location }) {
    const data = await api('/api/traceroute', {
      method: 'POST', body: JSON.stringify({ host, max_hops: Number(max_hops), location: location || undefined }),
    });
    const rows = data.hops.map((h) => {
      const ip = h.ip ? escapeHtml(h.ip) : '<span class="dim">*</span>';
      const hostname = h.hostname ? escapeHtml(h.hostname) : '<span class="dim">—</span>';
      const lat = h.latency_ms != null ? `${h.latency_ms} ms` : '<span class="dim">—</span>';
      return `<tr><td>${h.n}</td><td class="nowrap">${ip}</td><td>${hostname}</td><td class="nowrap">${lat}</td></tr>`;
    }).join('');
    const html =
      `<p class="label">traceroute ${escapeHtml(host)} · ${data.hops.length} hop(s)</p>` +
      `<table aria-label="Traceroute hops">` +
      `<tr><th>#</th><th>IP</th><th>Host</th><th>Latency</th></tr>${rows}</table>`;
    return { html, summary: `${data.hops.length} hop(s)` };
  },

  async port({ host, port, timeout, location }) {
    const data = await api('/api/port', {
      method: 'POST',
      body: JSON.stringify({ host, port: Number(port), timeout: Number(timeout), location: location || undefined }),
    });
    const cls = data.status === 'open' ? 'ok' : data.status === 'timeout' ? 'warn' : 'err';
    const html =
      `<p><span class="label">${escapeHtml(host)}:${data.port}</span> &rarr; ` +
      `<span class="${cls}"><strong>${escapeHtml(data.status)}</strong></span></p>`;
    return { html, summary: `${host}:${data.port} ${data.status}` };
  },

  async rdns({ ip }) {
    const data = await api('/api/rdns', { method: 'POST', body: JSON.stringify({ ip }) });
    const htmlOut = `<p><span class="label">${escapeHtml(data.ip)}</span> &rarr; <span class="ok">${escapeHtml(data.hostname)}</span></p>`;
    return { html: htmlOut, summary: data.hostname };
  },

  async whois({ target }) {
    const data = await api('/api/whois', { method: 'POST', body: JSON.stringify({ target }) });
    const ns = (data.nameservers || []).map((n) => escapeHtml(n)).join('<br>') || '<span class="dim">—</span>';
    const fmt = (v) => v ? escapeHtml(Array.isArray(v) ? v[0] : v) : '<span class="dim">—</span>';
    const htmlOut =
      `<table aria-label="WHOIS summary">` +
      `<tr><th>Registrar</th><td>${fmt(data.registrar)}</td></tr>` +
      `<tr><th>Created</th><td>${fmt(data.created)}</td></tr>` +
      `<tr><th>Expires</th><td>${fmt(data.expires)}</td></tr>` +
      `<tr><th>Name servers</th><td>${ns}</td></tr>` +
      `</table>` +
      `<details><summary class="label">raw record</summary><pre>${escapeHtml(data.raw || '')}</pre></details>`;
    return { html: htmlOut, summary: data.registrar || target };
  },

  async headers() {
    const data = await api('/api/headers', { method: 'GET' });
    const entries = Object.entries(data.headers || {});
    const rows = entries.map(([k, v]) =>
      `<tr><th class="nowrap">${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`
    ).join('');
    const htmlOut =
      `<p class="label">${entries.length} header(s) sent by your browser</p>` +
      `<table aria-label="Request headers">${rows}</table>`;
    return { html: htmlOut, summary: `${entries.length} header(s)` };
  },

  async ssl({ host, port, location }) {
    const portNum = Number(port) || 443;
    const data = await api('/api/ssl', {
      method: 'POST', body: JSON.stringify({ host, port: portNum, location: location || undefined }),
    });
    const days = data.days_remaining;
    let cls = 'ok';
    if (data.expired) cls = 'expired';
    else if (days <= 30) cls = 'warn';
    const sanList = (data.san || []).map(escapeHtml).join('<br>') || '<span class="dim">—</span>';
    const htmlOut =
      `<table aria-label="SSL certificate">` +
      `<tr><th>Host</th><td>${escapeHtml(host)}:${portNum}</td></tr>` +
      `<tr><th>Common name</th><td>${escapeHtml(data.subject.commonName || '—')}</td></tr>` +
      `<tr><th>Issuer</th><td>${escapeHtml(data.issuer.organizationName || '—')}</td></tr>` +
      `<tr><th>Valid from</th><td>${escapeHtml(formatDate(data.valid_from))}</td></tr>` +
      `<tr><th>Valid until</th><td>${escapeHtml(formatDate(data.valid_until))}</td></tr>` +
      `<tr><th>Days remaining</th><td class="${cls}"><strong>${days}</strong>${data.expired ? ' (expired)' : ''}</td></tr>` +
      `<tr><th>SAN</th><td>${sanList}</td></tr>` +
      `</table>`;
    return { html: htmlOut, summary: data.expired ? 'expired' : `${days}d left` };
  },

  async http({ url, location }) {
    const data = await api('/api/http', {
      method: 'POST', body: JSON.stringify({ url, location: location || undefined }),
    });
    const sc = data.status_code;
    let scCls = 'ok';
    if (sc >= 500) scCls = 'err';
    else if (sc >= 400) scCls = 'err';
    else if (sc >= 300) scCls = 'warn';
    const redirChain = (data.redirects && data.redirects.length)
      ? data.redirects.map(escapeHtml).join(' → ')
      : '<span class="dim">none</span>';
    const headerEntries = Object.entries(data.headers || {});
    const headerRows = headerEntries.map(
      ([k, v]) => `<tr><th class="nowrap">${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`
    ).join('');
    let tlsRow = '';
    if (data.tls) {
      const validCls = data.tls.valid ? 'ok' : 'warn';
      const days = data.tls.days_remaining;
      const daysFrag = (days != null) ? ` · <strong>${days}</strong>d left` : '';
      tlsRow = `<tr><th>TLS</th><td class="${validCls}">${data.tls.valid ? 'valid' : 'unauthorized'}${daysFrag}</td></tr>`;
    }
    const html =
      `<table aria-label="HTTP response summary">` +
      `<tr><th>URL</th><td>${escapeHtml(data.url)}</td></tr>` +
      `<tr><th>Status</th><td><strong class="${scCls}">${sc ?? '—'} ${escapeHtml(data.status_text || '')}</strong></td></tr>` +
      `<tr><th>Time</th><td>${data.response_time_ms ?? '—'} ms</td></tr>` +
      `<tr><th>Redirects</th><td>${redirChain}</td></tr>` +
      `${tlsRow}` +
      `</table>` +
      (headerEntries.length
        ? `<p class="label">key headers</p><table aria-label="HTTP headers">${headerRows}</table>`
        : '');
    return { html, summary: `${sc ?? '?'} · ${data.response_time_ms ?? '?'}ms` };
  },

  async mtr({ host, location }) {
    const data = await api('/api/mtr', {
      method: 'POST', body: JSON.stringify({ host, location: location || undefined }),
    });
    const rows = data.hops.map((h) => {
      const ip = h.ip ? escapeHtml(h.ip) : '<span class="dim">*</span>';
      const hostname = h.hostname ? escapeHtml(h.hostname) : '<span class="dim">—</span>';
      const loss = (h.loss_pct != null) ? `${h.loss_pct.toFixed(1)}%` : '<span class="dim">—</span>';
      const lossCls = (h.loss_pct === 0 || h.loss_pct == null) ? '' : h.loss_pct >= 50 ? 'err' : 'warn';
      const fmt = (v) => (v != null && v !== 0) ? `${v.toFixed(1)} ms` : (v === 0 ? '0 ms' : '<span class="dim">—</span>');
      return `<tr><td>${h.n}</td><td class="nowrap">${ip}</td><td>${hostname}</td>` +
             `<td class="nowrap ${lossCls}">${loss}</td>` +
             `<td class="nowrap">${fmt(h.avg_ms)}</td>` +
             `<td class="nowrap">${fmt(h.best_ms)}</td>` +
             `<td class="nowrap">${fmt(h.worst_ms)}</td></tr>`;
    }).join('');
    const html =
      `<p class="label">mtr ${escapeHtml(host)} · ${data.hops.length} hop(s)</p>` +
      `<table aria-label="MTR hops">` +
      `<tr><th>#</th><th>IP</th><th>Host</th><th>Loss</th><th>Avg</th><th>Best</th><th>Worst</th></tr>${rows}</table>`;
    return { html, summary: `${data.hops.length} hop(s)` };
  },
};

/* ---------------- share URL ---------------- */

function buildShareUrl(tool, payload) {
  const params = new URLSearchParams();
  params.set('tool', tool);
  for (const [k, v] of Object.entries(payload || {})) {
    if (v === null || v === undefined) continue;
    const s = String(v);
    if (s === '') continue;
    params.set(k, s);
  }
  const url = new URL(window.location.href);
  url.search = params.toString();
  url.hash = '';
  return url.toString();
}

/* ---------------- form binding ---------------- */

document.querySelectorAll('.tool-form').forEach((form) => {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const tool = form.dataset.tool;
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());

    if (!validateBeforeSend(tool, payload)) return;

    const btn = form.querySelector('.run-btn');
    btn.setAttribute('aria-busy', 'true');
    showLoading(toolLabel(tool));

    try {
      const { html: htmlOut, summary } = await runners[tool](payload);
      showResult(toolLabel(tool), htmlOut);
      // Update URL so the page is shareable + reloadable
      history.replaceState(null, '', buildShareUrl(tool, payload));
      pushHistory({
        tool,
        input: summarizeInput(tool, payload),
        result: summary,
        status: 'ok',
        ts: Date.now(),
      });
    } catch (err) {
      showError(toolLabel(tool), err);
      pushHistory({
        tool,
        input: summarizeInput(tool, payload),
        result: err.message || 'error',
        status: 'err',
        ts: Date.now(),
      });
    } finally {
      btn.removeAttribute('aria-busy');
    }
  });
});

function validateBeforeSend(tool, p) {
  const fail = (msg) => { showError(toolLabel(tool), { message: msg, code: 'bad_input' }); return false; };

  if (tool === 'headers') return true;
  if (tool === 'rdns') {
    if (!isValidIp(p.ip)) return fail('Enter a valid IPv4 or IPv6 address.');
  } else if (tool === 'port') {
    if (!p.host || !p.host.trim()) return fail('Host is required.');
    const port = Number(p.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('Port must be 1–65535.');
  } else if (tool === 'ssl') {
    if (!p.host || !p.host.trim()) return fail('Host is required.');
    if (p.port !== undefined && p.port !== '') {
      const port = Number(p.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('Port must be 1–65535.');
    }
  } else if (tool === 'http') {
    if (!p.url || !String(p.url).trim()) return fail('URL is required.');
  } else if (tool === 'mtr') {
    if (!p.host || !String(p.host).trim()) return fail('Host is required.');
  } else {
    const key = tool === 'whois' ? 'target' : 'host';
    if (!p[key] || !String(p[key]).trim()) return fail(`${tool === 'whois' ? 'Domain' : 'Host'} is required.`);
  }
  return true;
}

function summarizeInput(tool, p) {
  if (tool === 'dns') return `${p.host} ${p.type}`;
  if (tool === 'ping') return `${p.host} ×${p.count}`;
  if (tool === 'traceroute') return p.host;
  if (tool === 'mtr') return p.host;
  if (tool === 'port') return `${p.host}:${p.port}`;
  if (tool === 'rdns') return p.ip;
  if (tool === 'whois') return p.target;
  if (tool === 'ssl') return `${p.host}:${p.port || 443}`;
  if (tool === 'headers') return 'browser headers';
  if (tool === 'http') return p.url;
  return '';
}

function toolLabel(tool) {
  return ({
    dns: 'DNS lookup', ping: 'Ping', traceroute: 'Traceroute', mtr: 'MTR',
    port: 'Port check', rdns: 'Reverse DNS', whois: 'WHOIS',
    headers: 'Request headers', ssl: 'SSL certificate', http: 'HTTP request',
  })[tool] || tool;
}

function isValidIp(s) {
  if (!s) return false;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) {
    return s.split('.').every((p) => { const n = +p; return n >= 0 && n <= 255; });
  }
  return /^[0-9a-fA-F:]+$/.test(s) && s.includes(':');
}

/* ---------------- IP card ---------------- */

const ipStatus = document.querySelector('[data-ip-status]');
const ipFields = {
  ip: document.querySelector('[data-field="ip"]'),
  isp: document.querySelector('[data-field="isp"]'),
  asn: document.querySelector('[data-field="asn"]'),
  location: document.querySelector('[data-field="location"]'),
};

async function loadIp() {
  ipStatus.textContent = 'resolving…';
  ipStatus.removeAttribute('data-state');
  try {
    const data = await api('/api/ip');
    ipFields.ip.textContent = data.ip || '—';
    ipFields.isp.textContent = data.isp || '—';
    ipFields.asn.textContent = data.asn || '—';
    const loc = [data.city, data.country].filter(Boolean).join(', ');
    ipFields.location.textContent = loc || '—';
    ipStatus.textContent = 'ok';
    ipStatus.dataset.state = 'ok';
  } catch (err) {
    ipFields.ip.innerHTML = '<span class="dim">unavailable</span>';
    ipFields.isp.innerHTML = '<span class="dim">—</span>';
    ipFields.asn.innerHTML = '<span class="dim">—</span>';
    ipFields.location.innerHTML = '<span class="dim">—</span>';
    ipStatus.textContent = err.code || 'error';
    ipStatus.dataset.state = 'err';
  }
}

loadIp();

// Add collapse functionality to IP card
if (ipCard) {
  const collapseButton = ipCard.querySelector('.collapse-btn');
  if (collapseButton) {
    collapseButton.addEventListener('click', () => {
      const isCollapsed = ipCard.dataset.collapsed === 'true';
      ipCard.dataset.collapsed = String(!isCollapsed);
      collapseButton.textContent = isCollapsed ? 'collapse' : 'expand';
    });
  }
}

/* ---------------- copy + share buttons ---------------- */

document.addEventListener('click', async (e) => {
  const t = e.target.closest('.copy-btn');
  if (!t) return;

  // SHARE: copy current shareable URL
  if (t.matches('[data-share-result]')) {
    try {
      await navigator.clipboard.writeText(window.location.href);
      showToast('Link copied!');
      t.dataset.copied = 'true';
      const original = t.textContent;
      t.textContent = '✓ copied';
      setTimeout(() => { t.textContent = original; delete t.dataset.copied; }, 2000);
    } catch {
      showToast('Could not copy link');
    }
    return;
  }

  // COPY (result body or specific field)
  let text = '';
  if (t.matches('[data-copy-result]')) {
    text = lastResultText;
  } else if (t.dataset.copyTarget) {
    const node = document.querySelector(`[data-field="${t.dataset.copyTarget}"]`);
    text = (node && node.textContent || '').trim();
  }
  if (!text || text === '—') return;
  try {
    await navigator.clipboard.writeText(text);
    t.dataset.copied = 'true';
    const original = t.textContent;
    t.textContent = '✓ copied';
    setTimeout(() => { t.textContent = original; delete t.dataset.copied; }, 2000);
  } catch {
    // fallback noop
  }
});

/* ---------------- history ---------------- */

const historyList = document.querySelector('[data-history-list]');
const historyEmpty = document.querySelector('[data-history-empty]');
const historyClear = document.querySelector('[data-history-clear]');

function toggleHistory(btn) {
  const list = btn.closest('.history-section').querySelector('.history-list');
  list.classList.toggle('collapsed');
  btn.textContent = list.classList.contains('collapsed') ? 'expand' : 'collapse';
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(LS_KEYS.history);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveHistory(arr) {
  localStorage.setItem(LS_KEYS.history, JSON.stringify(arr.slice(0, HISTORY_MAX)));
}

function pushHistory(entry) {
  const arr = [entry, ...loadHistory().filter((h) => !(h.tool === entry.tool && h.input === entry.input))];
  saveHistory(arr);
  renderHistory();
}

function formatTime(ts) {
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(ts));
}

function renderHistory() {
  const arr = loadHistory();
  if (!arr.length) {
    historyList.innerHTML = '';
    historyList.appendChild(historyEmpty);
    return;
  }
  historyList.innerHTML = '';
  for (const h of arr) {
    const li = document.createElement('li');
    li.tabIndex = 0;
    li.dataset.tool = h.tool;
    li.dataset.input = h.input;
    li.setAttribute('role', 'button');
    li.setAttribute('aria-label', `Re-run ${h.tool} for ${h.input}`);
    li.innerHTML =
      `<span class="h-ts">${formatTime(h.ts)}</span>` +
      `<span class="h-tool">${escapeHtml(h.tool)}</span>` +
      `<span class="h-input">${escapeHtml(h.input)}</span>` +
      `<span class="h-result" data-status="${h.status === 'ok' ? 'ok' : 'err'}">${escapeHtml(h.result || '')}</span>`;
    li.addEventListener('click', () => rerun(h));
    li.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); rerun(h); }
    });
    historyList.appendChild(li);
  }
}

function rerun(h) {
  selectTab(h.tool);
  populateFromHistory(h);
  const form = document.querySelector(`.tool-form[data-tool="${h.tool}"]`);
  if (form) form.requestSubmit();
}

function populateFromHistory(h) {
  const { tool, input } = h;
  if (tool === 'dns') {
    const [host, type] = input.split(/\s+/);
    if (host) document.getElementById('dns-host').value = host;
    if (type) document.getElementById('dns-type').value = type;
  } else if (tool === 'ping') {
    const m = input.match(/^(\S+)\s*×(\d+)$/);
    if (m) {
      document.getElementById('ping-host').value = m[1];
      document.getElementById('ping-count').value = m[2];
    } else {
      document.getElementById('ping-host').value = input;
    }
  } else if (tool === 'traceroute') {
    document.getElementById('trace-host').value = input;
  } else if (tool === 'port') {
    const m = input.match(/^(.*):(\d+)$/);
    if (m) {
      document.getElementById('port-host').value = m[1];
      document.getElementById('port-port').value = m[2];
    }
  } else if (tool === 'rdns') {
    document.getElementById('rdns-ip').value = input;
  } else if (tool === 'whois') {
    document.getElementById('whois-target').value = input;
  } else if (tool === 'ssl') {
    const m = input.match(/^(.+):(\d+)$/);
    if (m) {
      document.getElementById('ssl-host').value = m[1];
      document.getElementById('ssl-port').value = m[2];
    }
  } else if (tool === 'mtr') {
    document.getElementById('mtr-host').value = input;
  } else if (tool === 'http') {
    document.getElementById('http-url').value = input;
  }
  // headers has no inputs
}

historyClear.addEventListener('click', () => {
  if (!confirm('Clear all history?')) return;
  localStorage.removeItem(LS_KEYS.history);
  renderHistory();
});

renderHistory();

/* ---------------- shortcuts dialog ---------------- */

const shortcutsDialog = document.getElementById('shortcuts-dialog');
const shortcutsBtn = document.getElementById('shortcuts-btn');

shortcutsBtn.addEventListener('click', () => shortcutsDialog.showModal());
shortcutsDialog.addEventListener('click', (e) => {
  if (e.target === shortcutsDialog || e.target.matches('[data-dialog-close]')) {
    shortcutsDialog.close();
  }
});

/* ---------------- global keyboard ---------------- */

document.addEventListener('keydown', (e) => {
  const tag = (e.target.tagName || '').toLowerCase();
  const inField = tag === 'input' || tag === 'select' || tag === 'textarea' || e.target.isContentEditable;
  if (e.ctrlKey || e.metaKey || e.altKey) return;

  if (e.key === '?' && !inField) {
    e.preventDefault();
    shortcutsDialog.showModal();
    return;
  }
  if (e.key === 'Escape') {
    if (shortcutsDialog.open) return;
    const active = document.querySelector('.tool-form:not([hidden]) input, [role="tabpanel"]:not([hidden]) input');
    if (active && document.activeElement === active) {
      active.value = '';
      return;
    }
  }
  if (!inField && TAB_KEY_MAP[e.key.toLowerCase()]) {
    e.preventDefault();
    selectTab(TAB_KEY_MAP[e.key.toLowerCase()], { focus: true });
  }
});

/* ---------------- init from URL query (last, after runners defined) ---------------- */

(function initFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const tool = params.get('tool');
  if (!tool || !runners[tool]) return;
  selectTab(tool);
  const form = document.querySelector(`.tool-form[data-tool="${tool}"]`);
  if (!form) return;
  for (const [k, v] of params.entries()) {
    if (k === 'tool') continue;
    const field = form.querySelector(`[name="${k}"]`);
    if (field) field.value = v;
  }
  // Auto-run the tool with the prefilled values
  form.requestSubmit();
})();
