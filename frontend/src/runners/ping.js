/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { formatLatency } from '../formatters/latency.js';
import { escapeHtml } from '../formatters/text.js';

export async function runPing({ host, count, location }) {
  const data = await api('/api/ping', {
    method: 'POST',
    body: JSON.stringify({ host, count: Number(count), location: location || undefined }),
  });
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
}
