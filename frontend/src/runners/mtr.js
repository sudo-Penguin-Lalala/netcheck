/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { formatLatency } from '../formatters/latency.js';
import { escapeHtml } from '../formatters/text.js';

export async function runMtr({ host, location }) {
  const data = await api('/api/mtr', {
    method: 'POST',
    body: JSON.stringify({ host, location: location || undefined }),
  });
  const rows = data.hops.map((h) => {
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
}
