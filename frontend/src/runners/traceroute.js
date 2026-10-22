/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { formatLatency } from '../formatters/latency.js';
import { escapeHtml } from '../formatters/text.js';

export async function runTraceroute({ host, max_hops, location }) {
  const data = await api('/api/traceroute', {
    method: 'POST',
    body: JSON.stringify({ host, max_hops: Number(max_hops), location: location || undefined }),
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
}
