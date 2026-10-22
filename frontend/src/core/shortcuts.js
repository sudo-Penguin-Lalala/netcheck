/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { TAB_KEY_MAP } from '../config.js';
import { showError } from '../ui/results.js';
import { selectTab } from '../ui/tabs.js';
import { state } from './state.js';

export function initShortcuts() {
  const shortcutsDialog = document.getElementById('shortcuts-dialog');
  const shortcutsBtn = document.getElementById('shortcuts-btn');

  if (shortcutsBtn && shortcutsDialog) {
    shortcutsBtn.addEventListener('click', () => shortcutsDialog.showModal());
  }

  if (shortcutsDialog) {
    shortcutsDialog.addEventListener('click', (e) => {
      if (e.target === shortcutsDialog || e.target.matches('[data-dialog-close]')) {
        shortcutsDialog.close();
      }
    });

    if (
      window.location.hash === '#shortcuts' ||
      new URLSearchParams(window.location.search).get('dialog') === 'shortcuts'
    ) {
      if (!shortcutsDialog.open) shortcutsDialog.showModal();
    }
  }

  document.addEventListener('keydown', (e) => {
    const tag = (e.target.tagName || '').toLowerCase();
    const inField = tag === 'input' || tag === 'select' || tag === 'textarea' || e.target.isContentEditable;

    // 1. Abort running probe with Escape or Ctrl+C
    const isCtrlC = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c' && !window.getSelection()?.toString();
    if (e.key === 'Escape' || isCtrlC) {
      if (state.currentAbortController) {
        e.preventDefault();
        state.abortCurrentProbe('user_abort');
        showError('Diagnostics Output', { code: 'cancelled', message: 'Probe cancelled by operator.' });
        return;
      }
    }

    if (e.ctrlKey || e.metaKey || e.altKey) return;

    // 2. Help shortcuts modal
    if (e.key === '?' && !inField) {
      e.preventDefault();
      if (shortcutsDialog) shortcutsDialog.showModal();
      return;
    }

    // 3. Escape when no probe running
    if (e.key === 'Escape') {
      if (shortcutsDialog && shortcutsDialog.open) return;
      const active = document.querySelector('.tool-form:not([hidden]) input, [role="tabpanel"]:not([hidden]) input');
      if (active && document.activeElement === active) {
        active.value = '';
        return;
      }
    }

    // 4. Enter to run current tool when not focused on an interactive element
    const isInteractive = inField || tag === 'button' || tag === 'a';
    if (e.key === 'Enter' && !isInteractive) {
      const activeForm = document.querySelector('[role="tabpanel"]:not([hidden]) .tool-form');
      if (activeForm) {
        e.preventDefault();
        activeForm.requestSubmit();
        return;
      }
    }

    // 5. Tool tab navigation keys (P, D, T, M, O, R, W, H, S, I, X)
    if (!inField && TAB_KEY_MAP[e.key.toLowerCase()]) {
      e.preventDefault();
      selectTab(TAB_KEY_MAP[e.key.toLowerCase()], { focus: true });
    }
  });
}
