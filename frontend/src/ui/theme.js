/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { LS_KEYS } from '../config.js';

export function applyTheme(theme) {
  const html = document.documentElement;
  const themeBtn = document.getElementById('theme-toggle');
  html.dataset.theme = theme;
  if (themeBtn) {
    themeBtn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
    const label = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
    themeBtn.setAttribute('aria-label', label);
    themeBtn.setAttribute('title', label);
  }
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => {
    if (!m.hasAttribute('media')) m.content = theme === 'light' ? '#f7f5f0' : '#0a0e14';
  });
}

export function initTheme() {
  const html = document.documentElement;
  const themeBtn = document.getElementById('theme-toggle');

  const stored = localStorage.getItem(LS_KEYS.theme);
  if (stored === 'light' || stored === 'dark') {
    applyTheme(stored);
  } else {
    const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    applyTheme(prefersLight ? 'light' : 'dark');
  }

  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next = html.dataset.theme === 'light' ? 'dark' : 'light';
      applyTheme(next);
      localStorage.setItem(LS_KEYS.theme, next);
    });
  }

  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
      if (!localStorage.getItem(LS_KEYS.theme)) {
        applyTheme(e.matches ? 'light' : 'dark');
      }
    });
  }
}
