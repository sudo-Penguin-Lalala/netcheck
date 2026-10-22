/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml } from '../formatters/text.js';

export async function runRdns({ ip }) {
  const data = await api('/api/rdns', { method: 'POST', body: JSON.stringify({ ip }) });
  const htmlOut = `<p><span class="label">${escapeHtml(data.ip)}</span> &rarr; <span class="ok">${escapeHtml(data.hostname)}</span></p>`;
  const rawText = `IP: ${data.ip}\nPTR (Reverse DNS): ${data.hostname}`;
  return { html: htmlOut, summary: data.hostname, rawText };
}
