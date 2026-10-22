/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml } from '../formatters/text.js';

export async function runDns({ host, type }) {
  const data = await api('/api/dns', { method: 'POST', body: JSON.stringify({ host, type }) });
  const rows = data.records.map((r) => `<tr><td class="nowrap">${escapeHtml(r)}</td></tr>`).join('');
  const html =
    `<p class="label">${escapeHtml(type)} records for ${escapeHtml(host)}` +
    ` <span class="dim">· ttl ${data.ttl}s · resolver ${escapeHtml(data.resolver)}</span></p>` +
    `<table aria-label="DNS records">${rows}</table>`;
  const rawText = data.records.map((r) => `${host}.\t${data.ttl}\tIN\t${type}\t${r}`).join('\n') +
    `\n\n;; Resolver: ${data.resolver}\n;; TTL: ${data.ttl}s`;
  return { html, summary: `${data.records.length} ${type} record(s)`, rawText };
}
