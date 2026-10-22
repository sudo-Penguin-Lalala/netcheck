/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { LS_KEYS } from '../config.js';
import { loadIp } from './ip_card.js';
import { showToast } from './toast.js';

let serverAuthRequired = false;

export function updateAuthStatusUI() {
  const tokenBtn = document.getElementById('token-btn');
  const tokenServerStatus = document.getElementById('token-server-status');
  const token = (localStorage.getItem(LS_KEYS.token) || '').trim();

  // Dynamic header button indicator
  if (tokenBtn) {
    if (token) {
      tokenBtn.dataset.authState = 'active';
      tokenBtn.setAttribute('title', 'Auth Token (Configured)');
      tokenBtn.setAttribute('aria-label', 'Auth Token (Configured)');
    } else if (serverAuthRequired) {
      tokenBtn.dataset.authState = 'required';
      tokenBtn.setAttribute('title', 'Auth Token Required');
      tokenBtn.setAttribute('aria-label', 'Auth Token Required');
    } else {
      delete tokenBtn.dataset.authState;
      tokenBtn.setAttribute('title', 'Configure Auth Token (Optional)');
      tokenBtn.setAttribute('aria-label', 'Configure Auth Token (Optional)');
    }
  }

  // Dynamic status box in modal dialog
  if (tokenServerStatus) {
    if (serverAuthRequired) {
      if (token) {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> Bearer authentication <span class="ok">enforced</span></p>` +
          `<p><strong>Local Authorization:</strong> Bearer token <span class="ok">active</span> (telemetry authorized)</p>`;
      } else {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> Bearer authentication <span class="warn">required</span></p>` +
          `<p><strong>Local Authorization:</strong> <span class="err">No token provided</span> — API queries require a valid Bearer token</p>`;
      }
    } else {
      if (token) {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> <span class="ok">Public Access</span> (AUTH_TOKEN not enforced)</p>` +
          `<p><strong>Local Authorization:</strong> Bearer token saved (forwarded in Authorization header)</p>`;
      } else {
        tokenServerStatus.innerHTML =
          `<p><strong>Endpoint Security Policy:</strong> <span class="ok">Public Access</span> (No authentication required)</p>` +
          `<p>Diagnostics endpoints open to anonymous queries. Token configuration is optional.</p>`;
      }
    }
  }
}

export async function checkServerAuth() {
  try {
    const res = await fetch('/api/healthz');
    if (res.ok) {
      const data = await res.json();
      serverAuthRequired = Boolean(data.auth_required);
      updateAuthStatusUI();
    }
  } catch {
    // ignore
  }
}

export function openTokenDialog() {
  const tokenDialog = document.getElementById('token-dialog');
  const tokenInput = document.getElementById('token-input');
  if (!tokenDialog) return;
  if (tokenInput) tokenInput.value = localStorage.getItem(LS_KEYS.token) || '';
  updateAuthStatusUI();
  if (!tokenDialog.open) tokenDialog.showModal();
}

export function initAuthDialog() {
  const tokenDialog = document.getElementById('token-dialog');
  const tokenBtn = document.getElementById('token-btn');
  const tokenForm = document.getElementById('token-form');
  const tokenInput = document.getElementById('token-input');
  const tokenClearBtn = document.getElementById('token-clear-btn');

  if (tokenBtn) tokenBtn.addEventListener('click', openTokenDialog);

  if (tokenDialog) {
    tokenDialog.addEventListener('click', (e) => {
      if (e.target === tokenDialog || e.target.matches('[data-token-close]')) {
        tokenDialog.close();
      }
    });
  }

  if (tokenForm) {
    tokenForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = (tokenInput ? tokenInput.value : '').trim();
      if (val) {
        localStorage.setItem(LS_KEYS.token, val);
        showToast('Auth token saved');
      } else {
        localStorage.removeItem(LS_KEYS.token);
        showToast('Auth token cleared');
      }
      updateAuthStatusUI();
      if (tokenDialog) tokenDialog.close();
      loadIp();
    });
  }

  if (tokenClearBtn) {
    tokenClearBtn.addEventListener('click', () => {
      localStorage.removeItem(LS_KEYS.token);
      if (tokenInput) tokenInput.value = '';
      showToast('Auth token cleared');
      updateAuthStatusUI();
      if (tokenDialog) tokenDialog.close();
      loadIp();
    });
  }

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('token')) {
    const t = urlParams.get('token');
    if (t) localStorage.setItem(LS_KEYS.token, t);
    urlParams.delete('token');
    const newSearch = urlParams.toString();
    const newUrl = window.location.pathname + (newSearch ? '?' + newSearch : '') + window.location.hash;
    window.history.replaceState(null, '', newUrl);
  }

  updateAuthStatusUI();
  checkServerAuth();

  if (window.location.hash === '#token' || urlParams.get('dialog') === 'token') {
    openTokenDialog();
  }
}
