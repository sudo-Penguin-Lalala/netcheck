/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { toolLabel } from '../config.js';
import { state } from '../core/state.js';
import { isValidIp } from '../formatters/text.js';
import { runners } from '../runners/index.js';
import { pushHistory } from './history.js';
import { showError, showLoading, showResult } from './results.js';

export function buildShareUrl(tool, payload) {
  const params = new URLSearchParams();
  params.set('tool', tool);
  for (const [k, v] of Object.entries(payload || {})) {
    if (v === null || v === undefined) continue;
    const s = String(v);
    if (s === '') continue;
    params.set(k, s);
  }
  const url = new URL(window.location.href);
  url.search = params.toString();
  url.hash = '';
  return url.toString();
}

export function validateBeforeSend(tool, p) {
  const fail = (msg) => {
    showError(toolLabel(tool), { message: msg, code: 'bad_input' });
    return false;
  };

  if (tool === 'headers') return true;
  if (tool === 'rdns') {
    if (!isValidIp(p.ip)) return fail('Enter a valid IPv4 or IPv6 address.');
  } else if (tool === 'port') {
    if (!p.host || !p.host.trim()) return fail('Host is required.');
    const port = Number(p.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('Port must be 1–65535.');
  } else if (tool === 'ssl') {
    if (!p.host || !p.host.trim()) return fail('Host is required.');
    if (p.port !== undefined && p.port !== '') {
      const port = Number(p.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('Port must be 1–65535.');
    }
  } else if (tool === 'http') {
    if (!p.url || !String(p.url).trim()) return fail('URL is required.');
  } else if (tool === 'mtr') {
    if (!p.host || !String(p.host).trim()) return fail('Host is required.');
  } else if (tool === 'ip-lookup') {
    if (!p.ip || !String(p.ip).trim()) return fail('IP address is required.');
    if (!isValidIp(p.ip)) return fail('Enter a valid IPv4 or IPv6 address.');
  } else {
    const key = tool === 'whois' ? 'target' : 'host';
    if (!p[key] || !String(p[key]).trim()) return fail(`${tool === 'whois' ? 'Domain' : 'Host'} is required.`);
  }
  return true;
}

export function summarizeInput(tool, p) {
  if (tool === 'dns') return `${p.host} ${p.type}`;
  if (tool === 'ping') return `${p.host} ×${p.count}`;
  if (tool === 'traceroute') return p.host;
  if (tool === 'mtr') return p.host;
  if (tool === 'port') return `${p.host}:${p.port}`;
  if (tool === 'rdns') return p.ip;
  if (tool === 'whois') return p.target;
  if (tool === 'ssl') return `${p.host}:${p.port || 443}`;
  if (tool === 'headers') return 'browser headers';
  if (tool === 'http') return p.url;
  if (tool === 'ip-lookup') return p.ip;
  return '';
}

export function initForms() {
  document.querySelectorAll('.tool-form').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const tool = form.dataset.tool;
      const fd = new FormData(form);
      const payload = Object.fromEntries(fd.entries());

      if (!validateBeforeSend(tool, payload)) return;

      state.abortCurrentProbe('new_submit');
      const controller = new AbortController();
      state.currentAbortController = controller;
      state.lastTelemetryPayload = { tool, payload };

      const btn = form.querySelector('.run-btn');
      if (btn) btn.setAttribute('aria-busy', 'true');
      showLoading(toolLabel(tool));

      try {
        const runner = runners[tool];
        if (!runner) throw new Error(`No runner found for tool: ${tool}`);
        const { html: htmlOut, summary, rawText } = await runner(payload);
        if (controller.signal.aborted) return;
        state.lastRawTelemetry = rawText || '';
        showResult(toolLabel(tool), htmlOut);

        history.replaceState(null, '', buildShareUrl(tool, payload));
        pushHistory({
          tool,
          input: summarizeInput(tool, payload),
          result: summary,
          status: 'ok',
          ts: Date.now(),
        });
      } catch (err) {
        if (controller.signal.aborted || err.code === 'cancelled') {
          showError(toolLabel(tool), { code: 'cancelled', message: 'Probe cancelled by operator.' });
          pushHistory({
            tool,
            input: summarizeInput(tool, payload),
            result: 'cancelled',
            status: 'warn',
            ts: Date.now(),
          });
          return;
        }
        showError(toolLabel(tool), err);
        pushHistory({
          tool,
          input: summarizeInput(tool, payload),
          result: err.message || 'error',
          status: 'err',
          ts: Date.now(),
        });
      } finally {
        if (btn) btn.removeAttribute('aria-busy');
        if (state.currentAbortController === controller) {
          state.currentAbortController = null;
        }
      }
    });
  });
}
