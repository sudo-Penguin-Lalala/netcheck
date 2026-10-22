/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { state } from '../core/state.js';
import { escapeHtml } from '../formatters/text.js';

const resultSection = document.querySelector('.result-section');
const resultTitle = document.querySelector('[data-result-title]');
const resultBody = document.querySelector('[data-result-body]');

export function showResult(title, htmlContent) {
  if (state.loadingTimer) {
    clearInterval(state.loadingTimer);
    state.loadingTimer = null;
  }
  if (!resultSection || !resultTitle || !resultBody) return;

  resultSection.hidden = false;
  resultTitle.textContent = `> ${title}`;
  resultBody.innerHTML = '';
  if (typeof htmlContent === 'string') {
    resultBody.innerHTML = htmlContent;
  } else if (htmlContent instanceof Node) {
    resultBody.appendChild(htmlContent);
  }
  resultSection.setAttribute('aria-busy', 'false');
  state.lastResultText = resultBody.innerText;
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

export function showLoading(title) {
  if (state.loadingTimer) {
    clearInterval(state.loadingTimer);
    state.loadingTimer = null;
  }
  if (!resultSection || !resultTitle || !resultBody) return;

  resultSection.hidden = false;
  resultTitle.textContent = `> ${title}`;
  resultBody.replaceChildren();

  const p = document.createElement('p');
  p.className = 'loading';
  const sp = document.createElement('span');
  sp.className = 'spinner';
  sp.setAttribute('aria-hidden', 'true');
  const lbl = document.createElement('span');
  lbl.className = 'label';
  lbl.textContent = 'Executing telemetry probe…';
  const el = document.createElement('span');
  el.className = 'dim';
  el.setAttribute('data-elapsed', '');
  el.textContent = '0.0s';

  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'cancel-probe-btn';
  cancelBtn.textContent = 'Cancel (Esc)';
  cancelBtn.setAttribute('aria-label', 'Cancel running probe');
  cancelBtn.addEventListener('click', () => {
    state.abortCurrentProbe('user_click');
    showError(title, { code: 'cancelled', message: 'Probe cancelled by operator.' });
  });

  p.append(sp, lbl, el, cancelBtn);
  resultBody.appendChild(p);
  resultSection.setAttribute('aria-busy', 'true');
  state.lastResultText = '';
  state.lastRawTelemetry = '';

  const start = performance.now();
  state.loadingTimer = setInterval(() => {
    if (!el.isConnected) {
      if (state.loadingTimer) {
        clearInterval(state.loadingTimer);
        state.loadingTimer = null;
      }
      return;
    }
    el.textContent = `${((performance.now() - start) / 1000).toFixed(1)}s`;
  }, 100);
}

export function showError(title, err) {
  if (state.loadingTimer) {
    clearInterval(state.loadingTimer);
    state.loadingTimer = null;
  }
  if (!resultSection || !resultTitle || !resultBody) return;

  resultSection.hidden = false;
  resultTitle.textContent = `> ${title} (error)`;

  const isAuthError = err.status === 401 || err.code === 'unauthorized';
  if (isAuthError) {
    resultBody.innerHTML =
      `<div class="error-card">` +
      `<p class="err-title"><strong>${escapeHtml(err.code || 'unauthorized')}</strong>: ${escapeHtml(err.message || 'Authentication required')}</p>` +
      `<p class="err-hint">This instance is configured with <code>AUTH_TOKEN</code>. Provide a valid Bearer token to execute remote probes.</p>` +
      `<button type="button" class="retry-btn" data-auth-prompt>Enter Auth Token</button>` +
      `</div>`;
    const promptBtn = resultBody.querySelector('[data-auth-prompt]');
    if (promptBtn) {
      promptBtn.addEventListener('click', () => {
        const dialog = document.getElementById('token-dialog');
        if (dialog && !dialog.open) dialog.showModal();
      });
    }
  } else {
    resultBody.innerHTML = `<p class="err"><strong>${escapeHtml(err.code || 'error')}</strong>: ${escapeHtml(err.message || 'Probe execution failed.')}</p>`;
  }

  resultSection.setAttribute('aria-busy', 'false');
  state.lastResultText = `ERROR: ${err.code || 'error'}: ${err.message || 'Probe execution failed.'}`;
  state.lastRawTelemetry = state.lastResultText;
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
