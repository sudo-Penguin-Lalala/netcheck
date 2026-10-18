/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

/* NetCheck early init - executes synchronously in <head> before DOM paint to eliminate flashes */
(function() {
  try {
    var storedTheme = localStorage.getItem('nc.theme.v1');
    if (storedTheme === 'light' || storedTheme === 'dark') {
      document.documentElement.dataset.theme = storedTheme;
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      document.documentElement.dataset.theme = 'light';
    } else {
      document.documentElement.dataset.theme = 'dark';
    }

    if (localStorage.getItem('nc.ip_collapsed.v1') === 'true') {
      document.documentElement.dataset.ipCollapsed = 'true';
    } else {
      document.documentElement.dataset.ipCollapsed = 'false';
    }

    if (localStorage.getItem('nc.history_collapsed.v1') === 'true') {
      document.documentElement.dataset.historyCollapsed = 'true';
    } else {
      document.documentElement.dataset.historyCollapsed = 'false';
    }
  } catch (e) {
    // Graceful fallback if localStorage is disabled or restricted
  }
})();
