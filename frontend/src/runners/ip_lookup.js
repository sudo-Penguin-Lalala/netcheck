/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml } from '../formatters/text.js';

export async function runIpLookup({ ip }) {
  const data = await api(`/api/ip-lookup?ip=${encodeURIComponent(ip)}`, { method: 'GET' });
  const fmt = (v) => v ? escapeHtml(v) : '<span class="dim">—</span>';
  const asnDisplay = data.asn ? (String(data.asn).toUpperCase().startsWith('AS') ? data.asn : `AS${data.asn}`) : '—';
  const htmlOut =
    `<p class="label">ip geolocation · ${escapeHtml(data.ip)}</p>` +
    `<table aria-label="IP lookup summary">` +
    `<tr><th>IP</th><td><strong>${escapeHtml(data.ip)}</strong></td></tr>` +
    `<tr><th>Location</th><td>${fmt(data.city)}, ${fmt(data.region)}, ${fmt(data.country)} (${fmt(data.continent)})</td></tr>` +
    `<tr><th>ASN</th><td>${escapeHtml(asnDisplay)} ${fmt(data.org)}</td></tr>` +
    `<tr><th>ISP</th><td>${fmt(data.isp)}</td></tr>` +
    `<tr><th>Timezone</th><td>${fmt(data.timezone)} (${fmt(data.utc)})</td></tr>` +
    `</table>`;
  const rawText = `IP Address: ${data.ip}\nLocation: ${data.city}, ${data.region}, ${data.country} (${data.continent})\nASN: ${asnDisplay} ${data.org || ''}\nISP: ${data.isp || '—'}\nTimezone: ${data.timezone || '—'} (${data.utc || '—'})`;
  return { html: htmlOut, summary: `${data.city || '—'}, ${data.country || '—'}`, rawText };
}
