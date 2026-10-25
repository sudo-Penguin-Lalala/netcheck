/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { LS_KEYS } from '../config.js';
import { escapeHtml } from '../formatters/text.js';
import { selectTab } from './tabs.js';

export const HISTORY_MAX = 50;

export function loadHistory() {
  try {
    const raw = localStorage.getItem(LS_KEYS.history);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function saveHistory(arr) {
  localStorage.setItem(LS_KEYS.history, JSON.stringify(arr.slice(0, HISTORY_MAX)));
}

export function pushHistory(entry) {
  const arr = [entry, ...loadHistory().filter((h) => !(h.tool === entry.tool && h.input === entry.input))];
  saveHistory(arr);
  renderHistory();
}

function formatTime(ts) {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(ts));
}

export function populateFromHistory(h) {
  const { tool, input } = h;
  if (tool === 'dns') {
    const [host, type] = input.split(/\s+/);
    if (host) document.getElementById('dns-host').value = host;
    if (type) document.getElementById('dns-type').value = type;
  } else if (tool === 'ping') {
    const m = input.match(/^(\S+)\s*×(\d+)$/);
    if (m) {
      document.getElementById('ping-host').value = m[1];
      document.getElementById('ping-count').value = m[2];
    } else {
      document.getElementById('ping-host').value = input;
    }
  } else if (tool === 'traceroute') {
    document.getElementById('trace-host').value = input;
  } else if (tool === 'port') {
    const m = input.match(/^(.*):(\d+)$/);
    if (m) {
      document.getElementById('port-host').value = m[1];
      document.getElementById('port-port').value = m[2];
    }
  } else if (tool === 'rdns') {
    document.getElementById('rdns-ip').value = input;
  } else if (tool === 'whois') {
    document.getElementById('whois-target').value = input;
  } else if (tool === 'ssl') {
    const m = input.match(/^(.+):(\d+)$/);
    if (m) {
      document.getElementById('ssl-host').value = m[1];
      document.getElementById('ssl-port').value = m[2];
    }
  } else if (tool === 'mtr') {
    document.getElementById('mtr-host').value = input;
  } else if (tool === 'http') {
    document.getElementById('http-url').value = input;
  } else if (tool === 'ip-lookup') {
    document.getElementById('ipl-host').value = input;
  }
}

export function rerunHistory(h) {
  selectTab(h.tool);
  populateFromHistory(h);
  const form = document.querySelector(`.tool-form[data-tool="${h.tool}"]`);
  if (form) form.requestSubmit();
}

export function renderHistory() {
  const historyList = document.querySelector('[data-history-list]');
  if (!historyList) return;

  const arr = loadHistory();
  if (!arr.length) {
    historyList.innerHTML = '<li class="history-empty" data-history-empty>No queries logged in current session.</li>';
    return;
  }
  historyList.innerHTML = '';
  for (const h of arr) {
    const li = document.createElement('li');
    li.tabIndex = 0;
    li.dataset.tool = h.tool;
    li.dataset.input = h.input;
    li.setAttribute('role', 'button');
    li.setAttribute('aria-label', `Re-run ${h.tool} for ${h.input}`);
    li.innerHTML =
      `<span class="h-ts">${formatTime(h.ts)}</span>` +
      `<span class="h-tool">${escapeHtml(h.tool)}</span>` +
      `<span class="h-input">${escapeHtml(h.input)}</span>` +
      `<span class="h-result" data-status="${h.status === 'ok' ? 'ok' : 'err'}">${escapeHtml(h.result || '')}</span>`;
    li.addEventListener('click', () => rerunHistory(h));
    li.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        rerunHistory(h);
      }
    });
    historyList.appendChild(li);
  }
}

export function initHistory() {
  const historySection = document.querySelector('.history-section');
  const historyClear = document.querySelector('[data-history-clear]');

  if (historySection) {
    const histCollapseBtn = historySection.querySelector('.collapse-btn');
    const storedHist = localStorage.getItem(LS_KEYS.historyCollapsed);
    const isHistCollapsed = storedHist === 'true';
    historySection.dataset.collapsed = String(isHistCollapsed);
    document.documentElement.dataset.historyCollapsed = String(isHistCollapsed);

    if (histCollapseBtn) {
      histCollapseBtn.addEventListener('click', () => {
        const isCollapsed =
          document.documentElement.dataset.historyCollapsed === 'true' ||
          historySection.dataset.collapsed === 'true';
        const nextCollapsed = !isCollapsed;
        historySection.dataset.collapsed = String(nextCollapsed);
        document.documentElement.dataset.historyCollapsed = String(nextCollapsed);
        localStorage.setItem(LS_KEYS.historyCollapsed, String(nextCollapsed));
      });
    }
  }

  if (historyClear) {
    historyClear.addEventListener('click', () => {
      if (!confirm('Clear all history?')) return;
      localStorage.removeItem(LS_KEYS.history);
      renderHistory();
    });
  }

  renderHistory();
}
