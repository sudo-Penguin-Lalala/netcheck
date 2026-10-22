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
  token: 'nc.token.v1',
  ipCollapsed: 'nc.ip_collapsed.v1',
  historyCollapsed: 'nc.history_collapsed.v1',
};
const HISTORY_MAX = 10;
const TAB_KEY_MAP = {
  d: 'dns', p: 'ping', t: 'traceroute', m: 'mtr',
  o: 'port', r: 'rdns', w: 'whois',
  h: 'headers', s: 'ssl', i: 'ip-lookup', x: 'http',
};

/* ---------------- theme ---------------- */

const html = document.documentElement;
const themeBtn = document.getElementById('theme-toggle');

function applyTheme(theme) {
  html.dataset.theme = theme;
  themeBtn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
  const label = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  themeBtn.setAttribute('aria-label', label);
  themeBtn.setAttribute('title', label);
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

/* ---------------- state & request lifecycle ---------------- */

let currentAbortController = null;
let lastTelemetryPayload = null;
let lastRawTelemetry = '';

function abortCurrentProbe(reason = 'aborted') {
  if (currentAbortController) {
    currentAbortController.abort();
    currentAbortController = null;
  }
  if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
  document.querySelectorAll('.run-btn[aria-busy="true"]').forEach((b) => b.removeAttribute('aria-busy'));
  if (resultSection) {
    resultSection.setAttribute('aria-busy', 'false');
  }
}

function latencyBand(ms) {
  if (ms == null || isNaN(ms)) return 'high';
  if (ms < 50) return 'low';
  if (ms <= 150) return 'mid';
  return 'high';
}

function formatLatency(ms) {
  if (ms == null) return '<span class="dim">—</span>';
  const band = latencyBand(ms);
  const val = typeof ms === 'number' ? ms.toFixed(1) : ms;
  return `<span class="latency-val" data-latency-band="${band}">${val} ms</span>`;
}

/* ---------------- tabs ---------------- */

const tabs = [...document.querySelectorAll('[role="tab"]')];
const panels = [...document.querySelectorAll('[role="tabpanel"]')];

function selectTab(tool, { focus = false } = {}) {
  // Cancel any running probe if user navigates to another tab
  if (currentAbortController) {
    abortCurrentProbe('tab_switch');
  }
  tabs.forEach((t) => {
    const active = t.dataset.tool === tool;
    t.setAttribute('aria-selected', active ? 'true' : 'false');
    t.tabIndex = active ? 0 : -1;
    if (active) {
      if (focus) t.focus();
      t.scrollIntoView({ inline: 'center', block: 'nearest', behavior: 'smooth' });
    }
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
  const token = localStorage.getItem(LS_KEYS.token);
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const opts = {
    ...options,
    headers: { ...headers, ...(options.headers || {}) },
    signal: options.signal || (currentAbortController ? currentAbortController.signal : undefined),
  };
  let resp;
  try {
    resp = await fetch(path, opts);
  } catch (err) {
    if (err.name === 'AbortError') {
      const abortErr = new Error('Probe cancelled by operator');
      abortErr.code = 'cancelled';
      abortErr.isAbort = true;
      throw abortErr;
    }
    throw err;
  }
  let body = null;
  try { body = await resp.json(); } catch { /* non-json */ }
  if (!resp.ok) {
    if (resp.status === 401 && typeof openTokenDialog === 'function') {
      openTokenDialog();
    }
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
  if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
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
  if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
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
  lbl.textContent = 'Executing telemetry probe…';
  const el = document.createElement('span');
  el.className = 'dim';
  el.setAttribute('data-elapsed', '');
  el.textContent = '0.0s';
  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'cancel-probe-btn';
  cancelBtn.textContent = 'Cancel (Esc)';
  cancelBtn.setAttribute('aria-label', 'Cancel running probe');
  cancelBtn.addEventListener('click', () => {
    abortCurrentProbe('user_click');
    showError(title, { code: 'cancelled', message: 'Probe cancelled by operator.' });
  });

  p.append(sp, lbl, el, cancelBtn);
  resultBody.appendChild(p);
  resultSection.setAttribute('aria-busy', 'true');
  lastResultText = '';
  lastRawTelemetry = '';
  const start = performance.now();
  loadingTimer = setInterval(() => {
    if (!el.isConnected) {
      clearInterval(loadingTimer);
      loadingTimer = null;
      return;
    }
    el.textContent = `${((performance.now() - start) / 1000).toFixed(1)}s`;
  }, 100);
}

function showError(title, err) {
  if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
  resultSection.hidden = false;
  resultTitle.textContent = `> ${title}`;
  const code = err.code || 'error';
  const msg = escapeHtml(err.message || 'Request failed');
  resultBody.innerHTML = `<div class="err"><strong>${escapeHtml(code)}</strong><br>${msg}</div>`;
  resultSection.setAttribute('aria-busy', 'false');
  lastResultText = resultBody.innerText;
  lastRawTelemetry = `ERROR: ${code}\n${err.message || 'Request failed'}`;
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
    const rawText = data.records.map((r) => `${host}.\t${data.ttl}\tIN\t${type}\t${r}`).join('\n') +
      `\n\n;; Resolver: ${data.resolver}\n;; TTL: ${data.ttl}s`;
    return { html, summary: `${data.records.length} ${type} record(s)`, rawText };
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
      `<tr><th>min</th><td>${formatLatency(data.min)}</td>` +
      `    <th>avg</th><td>${formatLatency(data.avg)}</td>` +
      `    <th>max</th><td>${formatLatency(data.max)}</td></tr>` +
      `</table>` +
      `<details><summary class="label">raw output</summary><pre>${escapeHtml(data.raw)}</pre></details>`;
    const rawText = data.raw ? data.raw.trim() :
      `--- ${host} ping statistics ---\n${data.packets_sent} packets transmitted, ${data.packets_recv} received, ${loss} packet loss\nrtt min/avg/max = ${data.min}/${data.avg}/${data.max} ms`;
    return { html, summary: `${data.packets_recv}/${data.packets_sent} · ${data.avg}ms`, rawText };
  },

  async traceroute({ host, max_hops, location }) {
    const data = await api('/api/traceroute', {
      method: 'POST', body: JSON.stringify({ host, max_hops: Number(max_hops), location: location || undefined }),
    });
    const rows = data.hops.map((h) => {
      const isTimeout = !h.ip;
      const ip = h.ip ? escapeHtml(h.ip) : '<span class="hop-timeout">* * * (Request Timed Out)</span>';
      const hostname = h.hostname ? escapeHtml(h.hostname) : '<span class="dim">—</span>';
      const lat = isTimeout ? '<span class="hop-timeout">*</span>' : formatLatency(h.latency_ms);
      return `<tr><td>${h.n}</td><td class="nowrap">${ip}</td><td>${hostname}</td><td class="nowrap">${lat}</td></tr>`;
    }).join('');
    const html =
      `<p class="label">traceroute ${escapeHtml(host)} · ${data.hops.length} hop(s)</p>` +
      `<table aria-label="Traceroute hops">` +
      `<tr><th>#</th><th>IP</th><th>Host</th><th>Latency</th></tr>${rows}</table>`;
    const rawText = `traceroute to ${host}, ${data.hops.length} hops max\n` +
      data.hops.map((h) => `${String(h.n).padStart(2)}  ${(h.ip || '* * *').padEnd(16)}  ${(h.hostname || '—').padEnd(30)}  ${h.latency_ms != null ? h.latency_ms + ' ms' : '*'}`).join('\n');
    return { html, summary: `${data.hops.length} hop(s)`, rawText };
  },

  async port({ host, port, timeout, location }) {
    const data = await api('/api/port', {
      method: 'POST',
      body: JSON.stringify({ host, port: Number(port), timeout: Number(timeout), location: location || undefined }),
    });
    const cls = data.status === 'open' ? 'ok' : data.status === 'timeout' ? 'warn' : 'err';
    const statusLabel = data.status === 'open'
      ? 'OPEN (TCP SYN-ACK received)'
      : data.status === 'timeout'
      ? `FILTERED / TIMEOUT (No response within ${timeout || 3}s — Dropped by firewall)`
      : 'CLOSED (TCP RST received — Port rejected by target)';
    const html =
      `<p><span class="label">${escapeHtml(host)}:${data.port}</span> &rarr; ` +
      `<span class="${cls}"><strong>${escapeHtml(statusLabel)}</strong></span></p>`;
    const rawText = `PORT CHECK\nTarget: ${host}:${data.port}\nStatus: ${data.status.toUpperCase()}\nDetails: ${statusLabel}`;
    return { html, summary: `${host}:${data.port} ${data.status.toUpperCase()}`, rawText };
  },

  async rdns({ ip }) {
    const data = await api('/api/rdns', { method: 'POST', body: JSON.stringify({ ip }) });
    const htmlOut = `<p><span class="label">${escapeHtml(data.ip)}</span> &rarr; <span class="ok">${escapeHtml(data.hostname)}</span></p>`;
    const rawText = `IP: ${data.ip}\nPTR (Reverse DNS): ${data.hostname}`;
    return { html: htmlOut, summary: data.hostname, rawText };
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
    const rawText = data.raw ? data.raw.trim() :
      `Domain: ${target}\nRegistrar: ${fmt(data.registrar)}\nCreated: ${fmt(data.created)}\nExpires: ${fmt(data.expires)}\nName Servers:\n${(data.nameservers || []).join('\n')}`;
    return { html: htmlOut, summary: data.registrar || target, rawText };
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
    const rawText = Object.entries(data.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
    return { html: htmlOut, summary: `${entries.length} header(s)`, rawText };
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
    const commonName = (data.subject && data.subject.commonName) || '—';
    const issuerName = (data.issuer && data.issuer.organizationName) || '—';
    const htmlOut =
      `<table aria-label="SSL certificate">` +
      `<tr><th>Host</th><td>${escapeHtml(host)}:${portNum}</td></tr>` +
      `<tr><th>Common name</th><td>${escapeHtml(commonName)}</td></tr>` +
      `<tr><th>Issuer</th><td>${escapeHtml(issuerName)}</td></tr>` +
      `<tr><th>Valid from</th><td>${escapeHtml(formatDate(data.valid_from))}</td></tr>` +
      `<tr><th>Valid until</th><td>${escapeHtml(formatDate(data.valid_until))}</td></tr>` +
      `<tr><th>Days remaining</th><td class="${cls}"><strong>${days}</strong>${data.expired ? ' (expired)' : ''}</td></tr>` +
      `<tr><th>SAN</th><td>${sanList}</td></tr>` +
      `</table>`;
    const rawText = `Host: ${host}:${portNum}\nCommon Name: ${commonName}\nIssuer: ${issuerName}\nValid From: ${formatDate(data.valid_from)}\nValid Until: ${formatDate(data.valid_until)}\nDays Remaining: ${days} (${data.expired ? 'EXPIRED' : 'VALID'})\nSubject Alternative Names (SAN):\n${(data.san || []).join('\n')}`;
    return { html: htmlOut, summary: data.expired ? 'expired' : `${days}d left`, rawText };
  },

  async 'ip-lookup'({ ip }) {
    const data = await api(`/api/ip-lookup?ip=${encodeURIComponent(ip)}`);
    const fmt = (v) => v != null ? escapeHtml(String(v)) : '<span class="dim">—</span>';
    const rawAsn = data.asn ? String(data.asn) : '';
    const asnDisplay = rawAsn ? (rawAsn.toUpperCase().startsWith('AS') ? rawAsn : `AS${rawAsn}`) : '<span class="dim">—</span>';
    const orgDisplay = data.org ? ` ${escapeHtml(data.org)}` : '';
    const htmlOut =
      `<table aria-label="IP lookup summary">` +
      `<tr><th>IP Address</th><td>${fmt(data.ip)}</td></tr>` +
      `<tr><th>Location</th><td>${fmt(data.city)}, ${fmt(data.region)}, ${fmt(data.country)} (${fmt(data.continent)})</td></tr>` +
      `<tr><th>ASN / Org</th><td>${asnDisplay}${orgDisplay}</td></tr>` +
      `<tr><th>ISP</th><td>${fmt(data.isp)}</td></tr>` +
      `<tr><th>Timezone</th><td>${fmt(data.timezone)} (${fmt(data.utc)})</td></tr>` +
      `</table>`;
    const rawText = `IP Address: ${data.ip}\nLocation: ${data.city}, ${data.region}, ${data.country} (${data.continent})\nASN: ${asnDisplay} ${data.org || ''}\nISP: ${data.isp || '—'}\nTimezone: ${data.timezone || '—'} (${data.utc || '—'})`;
    return { html: htmlOut, summary: `${data.city || '—'}, ${data.country || '—'}`, rawText };
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
      `<tr><th>Time</th><td>${formatLatency(data.response_time_ms)}</td></tr>` +
      `<tr><th>Redirects</th><td>${redirChain}</td></tr>` +
      `${tlsRow}` +
      `</table>` +
      (headerEntries.length
        ? `<p class="label">key headers</p><table aria-label="HTTP headers">${headerRows}</table>`
        : '');
    const rawText = `URL: ${data.url}\nHTTP Status: ${sc ?? '—'} ${data.status_text || ''}\nResponse Time: ${data.response_time_ms ?? '—'} ms\nRedirects: ${(data.redirects && data.redirects.length ? data.redirects.join(' -> ') : 'none')}\nTLS: ${data.tls ? (data.tls.valid ? 'Valid' : 'Invalid') : 'N/A'}\n\nKey Response Headers:\n` +
      Object.entries(data.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
    return { html, summary: `${sc ?? '?'} · ${data.response_time_ms ?? '?'}ms`, rawText };
  },

  async mtr({ host, location }) {
    const data = await api('/api/mtr', {
      method: 'POST', body: JSON.stringify({ host, location: location || undefined }),
    });
    const rows = data.hops.map((h) => {
      const isTimeout = !h.ip;
      const ip = h.ip ? escapeHtml(h.ip) : '<span class="hop-timeout">* * *</span>';
      const hostname = h.hostname ? escapeHtml(h.hostname) : '<span class="dim">—</span>';
      const loss = (h.loss_pct != null) ? `${h.loss_pct.toFixed(1)}%` : '<span class="hop-timeout">100.0%</span>';
      const lossCls = (h.loss_pct === 0) ? 'ok' : (h.loss_pct == null || h.loss_pct >= 50) ? 'err' : 'warn';
      return `<tr><td>${h.n}</td><td class="nowrap">${ip}</td><td>${hostname}</td>` +
             `<td class="nowrap ${lossCls}">${loss}</td>` +
             `<td class="nowrap">${formatLatency(h.avg_ms)}</td>` +
             `<td class="nowrap">${formatLatency(h.best_ms)}</td>` +
             `<td class="nowrap">${formatLatency(h.worst_ms)}</td></tr>`;
    }).join('');
    const html =
      `<p class="label">mtr ${escapeHtml(host)} · ${data.hops.length} hop(s)</p>` +
      `<table aria-label="MTR hops">` +
      `<tr><th>#</th><th>IP</th><th>Host</th><th>Loss</th><th>Avg</th><th>Best</th><th>Worst</th></tr>${rows}</table>`;
    const rawText = `HOST: ${host}\t\tLoss%\tAvg\tBest\tWorst\n` +
      data.hops.map((h) => `${String(h.n).padStart(2)}  ${(h.ip || '* * *').padEnd(16)}  ${(h.loss_pct != null ? h.loss_pct.toFixed(1) + '%' : '100%').padEnd(7)}  ${h.avg_ms != null ? h.avg_ms.toFixed(1) + 'ms' : '*'}  ${h.best_ms != null ? h.best_ms.toFixed(1) + 'ms' : '*'}  ${h.worst_ms != null ? h.worst_ms.toFixed(1) + 'ms' : '*'}`).join('\n');
    return { html, summary: `${data.hops.length} hop(s)`, rawText };
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

    abortCurrentProbe('new_submit');
    const controller = new AbortController();
    currentAbortController = controller;
    lastTelemetryPayload = { tool, payload };

    const btn = form.querySelector('.run-btn');
    btn.setAttribute('aria-busy', 'true');
    showLoading(toolLabel(tool));

    try {
      const { html: htmlOut, summary, rawText } = await runners[tool](payload);
      if (controller.signal.aborted) return;
      lastRawTelemetry = rawText || '';
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
      if (controller.signal.aborted || err.code === 'cancelled') {
        showError(toolLabel(tool), { code: 'cancelled', message: 'Probe cancelled by operator.' });
        pushHistory({
          tool,
          input: summarizeInput(tool, payload),
          result: 'cancelled',
          status: 'warn',
          ts: Date.now(),
        });
        return;
      }
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
      if (currentAbortController === controller) {
        currentAbortController = null;
      }
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
  } else if (tool === 'ip-lookup') {
    if (!p.ip || !String(p.ip).trim()) return fail('IP address is required.');
    if (!isValidIp(p.ip)) return fail('Enter a valid IPv4 or IPv6 address.');
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
  if (tool === 'ip-lookup') return p.ip;
  return '';
}

function toolLabel(tool) {
  return ({
    dns: 'DNS lookup', ping: 'Ping', traceroute: 'Traceroute', mtr: 'MTR',
    port: 'Port check', rdns: 'Reverse DNS', whois: 'WHOIS',
    headers: 'Request headers', ssl: 'SSL certificate',
    'ip-lookup': 'IP lookup', http: 'HTTP request',
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

const ipCard = document.querySelector('.ip-card');
const ipStatus = document.querySelector('[data-ip-status]');
const ipFields = {
  ipv4: document.querySelector('[data-field="ipv4"]'),
  ipv6: document.querySelector('[data-field="ipv6"]'),
  isp: document.querySelector('[data-field="isp"]'),
  asn: document.querySelector('[data-field="asn"]'),
  location: document.querySelector('[data-field="location"]'),
};

async function loadIp() {
  if (ipStatus) {
    ipStatus.textContent = 'Resolving endpoints…';
    ipStatus.removeAttribute('data-state');
  }
  try {
    const data = await api('/api/ip');
    if (data.ip) {
      if (data.ip.includes(':')) {
        if (ipFields.ipv6) ipFields.ipv6.textContent = data.ip;
      } else {
        if (ipFields.ipv4) ipFields.ipv4.textContent = data.ip;
      }
    }
    if (ipFields.isp) ipFields.isp.textContent = data.isp || '—';
    if (ipFields.asn) ipFields.asn.textContent = data.asn || '—';
    const loc = [data.city, data.country].filter(Boolean).join(', ');
    if (ipFields.location) ipFields.location.textContent = loc || '—';
    if (ipStatus) {
      ipStatus.textContent = 'Established';
      ipStatus.dataset.state = 'ok';
    }
    probeDualStackIps();
  } catch (err) {
    if (ipFields.ipv4) ipFields.ipv4.innerHTML = '<span class="dim">unavailable</span>';
    if (ipFields.ipv6) ipFields.ipv6.innerHTML = '<span class="dim">unavailable</span>';
    if (ipFields.isp) ipFields.isp.innerHTML = '<span class="dim">—</span>';
    if (ipFields.asn) ipFields.asn.innerHTML = '<span class="dim">—</span>';
    if (ipFields.location) ipFields.location.innerHTML = '<span class="dim">—</span>';
    if (ipStatus) {
      ipStatus.textContent = err.code || 'error';
      ipStatus.dataset.state = 'err';
    }
  }
}

async function probeDualStackIps() {
  fetch('https://api4.ipify.org?format=json', { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json())
    .then((d) => {
      if (d.ip && ipFields.ipv4) ipFields.ipv4.textContent = d.ip;
    })
    .catch(() => {
      if (ipFields.ipv4 && (!ipFields.ipv4.textContent || ipFields.ipv4.textContent === 'Probing…' || ipFields.ipv4.textContent === 'detecting…')) {
        ipFields.ipv4.innerHTML = '<span class="dim">—</span>';
      }
    });

  fetch('https://api6.ipify.org?format=json', { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json())
    .then((d) => {
      if (d.ip && ipFields.ipv6) ipFields.ipv6.textContent = d.ip;
    })
    .catch(() => {
      if (ipFields.ipv6 && (!ipFields.ipv6.textContent || ipFields.ipv6.textContent === 'Probing…' || ipFields.ipv6.textContent === 'detecting…')) {
        ipFields.ipv6.innerHTML = '<span class="dim">No IPv6 route (IPv4-only egress)</span>';
      }
    });
}

loadIp();

// Add collapse functionality to IP card with persistence
if (ipCard) {
  const collapseButton = ipCard.querySelector('.collapse-btn');
  const storedCollapsed = localStorage.getItem(LS_KEYS.ipCollapsed);
  const isInitialCollapsed = storedCollapsed === 'true';
  ipCard.dataset.collapsed = String(isInitialCollapsed);
  document.documentElement.dataset.ipCollapsed = String(isInitialCollapsed);

  if (collapseButton) {
    collapseButton.addEventListener('click', () => {
      const isCollapsed = document.documentElement.dataset.ipCollapsed === 'true' || ipCard.dataset.collapsed === 'true';
      const nextCollapsed = !isCollapsed;
      ipCard.dataset.collapsed = String(nextCollapsed);
      document.documentElement.dataset.ipCollapsed = String(nextCollapsed);
      localStorage.setItem(LS_KEYS.ipCollapsed, String(nextCollapsed));
    });
  }
}

/* ---------------- copy + share + rerun buttons ---------------- */

document.addEventListener('click', async (e) => {
  const t = e.target.closest('.copy-btn');
  if (!t) return;

  // RERUN: rerun last probe
  if (t.matches('[data-rerun-result]')) {
    let form = null;
    if (lastTelemetryPayload && lastTelemetryPayload.tool) {
      form = document.querySelector(`.tool-form[data-tool="${lastTelemetryPayload.tool}"]`);
    }
    if (!form) {
      form = document.querySelector('[role="tabpanel"]:not([hidden]) .tool-form');
    }
    if (form) {
      form.requestSubmit();
    }
    return;
  }

  // SHARE: copy current shareable URL
  if (t.matches('[data-share-result]')) {
    try {
      await navigator.clipboard.writeText(window.location.href);
      showToast('Shareable URL copied to clipboard');
      t.dataset.copied = 'true';
      const original = t.textContent;
      t.textContent = '✓ Copied';
      setTimeout(() => { t.textContent = original; delete t.dataset.copied; }, 2000);
    } catch {
      showToast('Clipboard access denied');
    }
    return;
  }

  // COPY (result body or specific field)
  let text = '';
  if (t.matches('[data-copy-result]')) {
    text = lastRawTelemetry || lastResultText;
  } else if (t.dataset.copyTarget) {
    const node = document.querySelector(`[data-field="${t.dataset.copyTarget}"]`);
    text = (node && node.textContent || '').trim();
  }
  if (!text || text === '—') return;
  try {
    await navigator.clipboard.writeText(text);
    t.dataset.copied = 'true';
    const original = t.textContent;
    t.textContent = '✓ Copied';
    setTimeout(() => { t.textContent = original; delete t.dataset.copied; }, 2000);
  } catch {
    // fallback noop
  }
});

/* ---------------- history ---------------- */

const historySection = document.querySelector('.history-section');
const historyList = document.querySelector('[data-history-list]');
const historyEmpty = document.querySelector('[data-history-empty]');
const historyClear = document.querySelector('[data-history-clear]');

if (historySection) {
  const histCollapseBtn = historySection.querySelector('.collapse-btn');
  const storedHist = localStorage.getItem(LS_KEYS.historyCollapsed);
  const isHistCollapsed = storedHist === 'true';
  historySection.dataset.collapsed = String(isHistCollapsed);
  document.documentElement.dataset.historyCollapsed = String(isHistCollapsed);

  if (histCollapseBtn) {
    histCollapseBtn.addEventListener('click', () => {
      const isCollapsed = document.documentElement.dataset.historyCollapsed === 'true' || historySection.dataset.collapsed === 'true';
      const nextCollapsed = !isCollapsed;
      historySection.dataset.collapsed = String(nextCollapsed);
      document.documentElement.dataset.historyCollapsed = String(nextCollapsed);
      localStorage.setItem(LS_KEYS.historyCollapsed, String(nextCollapsed));
    });
  }
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
  } else if (tool === 'ip-lookup') {
    document.getElementById('ipl-host').value = input;
  }
  // headers has no inputs
}

historyClear.addEventListener('click', () => {
  if (!confirm('Clear all history?')) return;
  localStorage.removeItem(LS_KEYS.history);
  renderHistory();
});

renderHistory();

/* ---------------- auth token dialog & dynamic status ---------------- */

const tokenDialog = document.getElementById('token-dialog');
const tokenBtn = document.getElementById('token-btn');
const tokenForm = document.getElementById('token-form');
const tokenInput = document.getElementById('token-input');
const tokenClearBtn = document.getElementById('token-clear-btn');
const tokenServerStatus = document.getElementById('token-server-status');

let serverAuthRequired = false;

function updateAuthStatusUI() {
  const token = (localStorage.getItem(LS_KEYS.token) || '').trim();

  // Dynamic header button indicator
  if (tokenBtn) {
    if (token) {
      tokenBtn.dataset.authState = 'active';
      tokenBtn.setAttribute('title', 'Auth Token (Configured)');
      tokenBtn.setAttribute('aria-label', 'Auth Token (Configured)');
    } else if (serverAuthRequired) {
      tokenBtn.dataset.authState = 'required';
      tokenBtn.setAttribute('title', 'Auth Token Required');
      tokenBtn.setAttribute('aria-label', 'Auth Token Required');
    } else {
      delete tokenBtn.dataset.authState;
      tokenBtn.setAttribute('title', 'Configure Auth Token (Optional)');
      tokenBtn.setAttribute('aria-label', 'Configure Auth Token (Optional)');
    }
  }

  // Dynamic status box in modal dialog
  if (tokenServerStatus) {
    if (serverAuthRequired) {
      if (token) {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> Bearer authentication <span class="ok">enforced</span></p>` +
          `<p><strong>Local Authorization:</strong> Bearer token <span class="ok">active</span> (telemetry authorized)</p>`;
      } else {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> Bearer authentication <span class="warn">required</span></p>` +
          `<p><strong>Local Authorization:</strong> <span class="err">No token provided</span> — API queries require a valid Bearer token</p>`;
      }
    } else {
      if (token) {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> <span class="ok">Public Access</span> (AUTH_TOKEN not enforced)</p>` +
          `<p><strong>Local Authorization:</strong> Bearer token saved (forwarded in Authorization header)</p>`;
      } else {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> <span class="ok">Public Access</span> (No authentication required)</p>` +
          `<p>Diagnostics endpoints open to anonymous queries. Token configuration is optional.</p>`;
      }
    }
  }
}

async function checkServerAuth() {
  try {
    const res = await fetch('/api/healthz');
    if (res.ok) {
      const data = await res.json();
      serverAuthRequired = Boolean(data.auth_required);
      updateAuthStatusUI();
    }
  } catch {
    // ignore
  }
}

function openTokenDialog() {
  if (!tokenDialog) return;
  if (tokenInput) tokenInput.value = localStorage.getItem(LS_KEYS.token) || '';
  updateAuthStatusUI();
  if (!tokenDialog.open) tokenDialog.showModal();
}

if (tokenBtn) tokenBtn.addEventListener('click', openTokenDialog);
if (tokenDialog) {
  tokenDialog.addEventListener('click', (e) => {
    if (e.target === tokenDialog || e.target.matches('[data-token-close]')) {
      tokenDialog.close();
    }
  });
}
if (tokenForm) {
  tokenForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const val = (tokenInput ? tokenInput.value : '').trim();
    if (val) {
      localStorage.setItem(LS_KEYS.token, val);
      showToast('Auth token saved');
    } else {
      localStorage.removeItem(LS_KEYS.token);
      showToast('Auth token cleared');
    }
    updateAuthStatusUI();
    if (tokenDialog) tokenDialog.close();
    loadIp();
  });
}
if (tokenClearBtn) {
  tokenClearBtn.addEventListener('click', () => {
    localStorage.removeItem(LS_KEYS.token);
    if (tokenInput) tokenInput.value = '';
    showToast('Auth token cleared');
    updateAuthStatusUI();
    if (tokenDialog) tokenDialog.close();
    loadIp();
  });
}

(function initAuthToken() {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('token')) {
    const t = urlParams.get('token');
    if (t) localStorage.setItem(LS_KEYS.token, t);
    urlParams.delete('token');
    const newSearch = urlParams.toString();
    const newUrl = window.location.pathname + (newSearch ? '?' + newSearch : '') + window.location.hash;
    window.history.replaceState(null, '', newUrl);
  }
  updateAuthStatusUI();
  checkServerAuth();
  if (window.location.hash === '#token' || urlParams.get('dialog') === 'token') {
    openTokenDialog();
  }
})();

/* ---------------- shortcuts dialog ---------------- */

const shortcutsDialog = document.getElementById('shortcuts-dialog');
const shortcutsBtn = document.getElementById('shortcuts-btn');

shortcutsBtn.addEventListener('click', () => shortcutsDialog.showModal());
shortcutsDialog.addEventListener('click', (e) => {
  if (e.target === shortcutsDialog || e.target.matches('[data-dialog-close]')) {
    shortcutsDialog.close();
  }
});
if (window.location.hash === '#shortcuts' || new URLSearchParams(window.location.search).get('dialog') === 'shortcuts') {
  if (shortcutsDialog && !shortcutsDialog.open) shortcutsDialog.showModal();
}

/* ---------------- global keyboard ---------------- */

document.addEventListener('keydown', (e) => {
  const tag = (e.target.tagName || '').toLowerCase();
  const inField = tag === 'input' || tag === 'select' || tag === 'textarea' || e.target.isContentEditable;

  // 1. Abort running probe with Escape or Ctrl+C
  const isCtrlC = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c' && !window.getSelection()?.toString();
  if (e.key === 'Escape' || isCtrlC) {
    if (currentAbortController) {
      e.preventDefault();
      abortCurrentProbe('user_abort');
      showError('Diagnostics Output', { code: 'cancelled', message: 'Probe cancelled by operator.' });
      return;
    }
  }

  if (e.ctrlKey || e.metaKey || e.altKey) return;

  // 2. Help shortcuts modal
  if (e.key === '?' && !inField) {
    e.preventDefault();
    if (shortcutsDialog) shortcutsDialog.showModal();
    return;
  }

  // 3. Escape when no probe running
  if (e.key === 'Escape') {
    if (shortcutsDialog && shortcutsDialog.open) return;
    const active = document.querySelector('.tool-form:not([hidden]) input, [role="tabpanel"]:not([hidden]) input');
    if (active && document.activeElement === active) {
      active.value = '';
      return;
    }
  }

  // 4. Enter to run current tool when not focused on an interactive element
  const isInteractive = inField || tag === 'button' || tag === 'a';
  if (e.key === 'Enter' && !isInteractive) {
    const activeForm = document.querySelector('[role="tabpanel"]:not([hidden]) .tool-form');
    if (activeForm) {
      e.preventDefault();
      activeForm.requestSubmit();
      return;
    }
  }

  // 5. Tool tab navigation keys (P, D, T, M, O, R, W, H, S, I, X)
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

window.requestAnimationFrame(() => {
  document.body.classList.remove('preload');
});
