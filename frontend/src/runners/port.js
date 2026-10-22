/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { api } from '../core/api.js';
import { escapeHtml } from '../formatters/text.js';

export async function runPort({ host, port, timeout, location }) {
  const data = await api('/api/port', {
    method: 'POST',
    body: JSON.stringify({ host, port: Number(port), timeout: Number(timeout), location: location || undefined }),
  });
  const cls = data.status === 'open' ? 'ok' : data.status === 'timeout' ? 'warn' : 'err';
  const statusLabel = data.status === 'open'
    ? 'OPEN (TCP SYN-ACK received)'
    : data.status === 'timeout'
    ? `FILTERED / TIMEOUT (No response within ${timeout || 3}s — Dropped by firewall)`
    : 'CLOSED (TCP RST received — Port rejected by target)';
  const html =
    `<p><span class="label">${escapeHtml(host)}:${data.port}</span> &rarr; ` +
    `<span class="${cls}"><strong>${escapeHtml(statusLabel)}</strong></span></p>`;
  const rawText = `PORT CHECK\nTarget: ${host}:${data.port}\nStatus: ${data.status.toUpperCase()}\nDetails: ${statusLabel}`;
  return { html, summary: `${host}:${data.port} ${data.status.toUpperCase()}`, rawText };
}
