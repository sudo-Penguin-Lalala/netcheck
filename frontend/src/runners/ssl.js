/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml, formatDate } from '../formatters/text.js';

export async function runSsl({ host, port, location }) {
  const portNum = Number(port) || 443;
  const data = await api('/api/ssl', {
    method: 'POST',
    body: JSON.stringify({ host, port: portNum, location: location || undefined }),
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
}
