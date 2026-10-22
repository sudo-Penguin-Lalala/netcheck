/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

/**
 * NetCheck Web Client — Entrypoint Module
 * Vanilla ES Module orchestrator with zero build dependencies.
 */

import { initShortcuts } from './src/core/shortcuts.js';
import { runners } from './src/runners/index.js';
import { initAuthDialog } from './src/ui/auth_dialog.js';
import { initClipboard } from './src/ui/clipboard.js';
import { initForms } from './src/ui/forms.js';
import { initHistory } from './src/ui/history.js';
import { initIpCard } from './src/ui/ip_card.js';
import { initTabs, selectTab } from './src/ui/tabs.js';
import { initTheme } from './src/ui/theme.js';

function initFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const tool = params.get('tool');
  if (!tool || !runners[tool]) return;
  selectTab(tool);
  const form = document.querySelector(`.tool-form[data-tool="${tool}"]`);
  if (!form) return;
  for (const [k, v] of params.entries()) {
    if (k === 'tool') continue;
    const field = form.querySelector(`[name="${k}"]`);
    if (field) field.value = v;
  }
  form.requestSubmit();
}

// Bootstrap NetCheck UI subsystems
initTheme();
initTabs();
initIpCard();
initHistory();
initAuthDialog();
initShortcuts();
initForms();
initClipboard();
initFromQuery();

window.requestAnimationFrame(() => {
  document.body.classList.remove('preload');
});
