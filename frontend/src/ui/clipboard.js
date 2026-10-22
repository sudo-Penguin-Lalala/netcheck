/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { state } from '../core/state.js';
import { showToast } from './toast.js';

export function initClipboard() {
  document.addEventListener('click', async (e) => {
    const t = e.target.closest('.copy-btn');
    if (!t) return;

    // RERUN: rerun last probe
    if (t.matches('[data-rerun-result]')) {
      let form = null;
      if (state.lastTelemetryPayload && state.lastTelemetryPayload.tool) {
        form = document.querySelector(`.tool-form[data-tool="${state.lastTelemetryPayload.tool}"]`);
      }
      if (!form) {
        form = document.querySelector('[role="tabpanel"]:not([hidden]) .tool-form');
      }
      if (form) {
        form.requestSubmit();
      }
      return;
    }

    // SHARE: copy current shareable URL
    if (t.matches('[data-share-result]')) {
      try {
        await navigator.clipboard.writeText(window.location.href);
        showToast('Shareable URL copied to clipboard');
        t.dataset.copied = 'true';
        const original = t.textContent;
        t.textContent = '✓ Copied';
        setTimeout(() => {
          t.textContent = original;
          delete t.dataset.copied;
        }, 2000);
      } catch {
        showToast('Clipboard access denied');
      }
      return;
    }

    // COPY (result body or specific field)
    let text = '';
    if (t.matches('[data-copy-result]')) {
      text = state.lastRawTelemetry || state.lastResultText;
    } else if (t.dataset.copyTarget) {
      const node = document.querySelector(`[data-field="${t.dataset.copyTarget}"]`);
      text = ((node && node.textContent) || '').trim();
    }
    if (!text || text === '—') return;
    try {
      await navigator.clipboard.writeText(text);
      t.dataset.copied = 'true';
      const original = t.textContent;
      t.textContent = '✓ Copied';
      setTimeout(() => {
        t.textContent = original;
        delete t.dataset.copied;
      }, 2000);
    } catch {
      // fallback noop
    }
  });
}
