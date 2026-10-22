/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml } from '../formatters/text.js';

export async function runWhois({ target }) {
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
}
