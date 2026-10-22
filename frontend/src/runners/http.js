/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { formatLatency } from '../formatters/latency.js';
import { escapeHtml } from '../formatters/text.js';

export async function runHttp({ url, location }) {
  const data = await api('/api/http', {
    method: 'POST', body: JSON.stringify({ url, location: location || undefined }),
  });
  const sc = data.status_code;
  const scCls = (sc >= 200 && sc < 300) ? 'ok' : (sc >= 300 && sc < 400) ? 'warn' : 'err';
  const redirChain = (data.redirects && data.redirects.length)
    ? data.redirects.map((r) => escapeHtml(r)).join(' &rarr; ')
    : '<span class="dim">none</span>';
  const tlsRow = data.tls
    ? `<tr><th>TLS</th><td>${data.tls.valid ? '<span class="ok">Valid certificate</span>' : '<span class="err">Invalid / untrusted</span>'}</td></tr>`
    : '';
  const headerEntries = Object.entries(data.headers || {});
  const headerRows = headerEntries.map(([k, v]) =>
    `<tr><th class="nowrap">${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`
  ).join('');
  const html =
    `<p class="label">http ${escapeHtml(data.url)}</p>` +
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
}
