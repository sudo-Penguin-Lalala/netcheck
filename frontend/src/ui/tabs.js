/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { LS_KEYS } from '../config.js';
import { state } from '../core/state.js';

export function selectTab(tool, { focus = false } = {}) {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const panels = [...document.querySelectorAll('[role="tabpanel"]')];

  // Cancel any running probe if user navigates to another tab
  if (state.currentAbortController) {
    state.abortCurrentProbe('tab_switch');
  }

  tabs.forEach((t) => {
    const active = t.dataset.tool === tool;
    t.setAttribute('aria-selected', active ? 'true' : 'false');
    t.tabIndex = active ? 0 : -1;
    if (active) {
      if (focus) t.focus();
      t.scrollIntoView({ inline: 'center', block: 'nearest', behavior: 'smooth' });
    }
  });

  panels.forEach((p) => {
    const active = p.id === `panel-${tool}`;
    p.hidden = !active;
  });

  localStorage.setItem(LS_KEYS.tab, tool);

  if (focus) {
    const next = document.querySelector(`#panel-${tool} input, #panel-${tool} select`);
    if (next) next.focus();
  }
}

export function initTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];

  tabs.forEach((t) => {
    t.addEventListener('click', () => selectTab(t.dataset.tool));
    t.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        const dir = e.key === 'ArrowRight' ? 1 : -1;
        const idx = tabs.indexOf(t);
        const next = tabs[(idx + dir + tabs.length) % tabs.length];
        selectTab(next.dataset.tool, { focus: true });
      } else if (e.key === 'Home') {
        e.preventDefault();
        selectTab(tabs[0].dataset.tool, { focus: true });
      } else if (e.key === 'End') {
        e.preventDefault();
        selectTab(tabs[tabs.length - 1].dataset.tool, { focus: true });
      }
    });
  });

  const stored = localStorage.getItem(LS_KEYS.tab);
  if (stored && tabs.some((t) => t.dataset.tool === stored)) {
    selectTab(stored);
  }
}
