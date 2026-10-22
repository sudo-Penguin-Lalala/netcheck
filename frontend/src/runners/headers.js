/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml } from '../formatters/text.js';

export async function runHeaders() {
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
}
