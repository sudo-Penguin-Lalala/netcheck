/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { LS_KEYS } from '../config.js';
import { api } from '../core/api.js';

export async function loadIp() {
  const ipStatus = document.querySelector('[data-ip-status]');
  const ipFields = {
    ipv4: document.querySelector('[data-field="ipv4"]'),
    ipv6: document.querySelector('[data-field="ipv6"]'),
    isp: document.querySelector('[data-field="isp"]'),
    asn: document.querySelector('[data-field="asn"]'),
    location: document.querySelector('[data-field="location"]'),
  };

  if (ipStatus) {
    ipStatus.textContent = 'Resolving endpoints…';
    ipStatus.removeAttribute('data-state');
  }

  try {
    const data = await api('/api/ip');
    if (data.ip) {
      if (data.ip.includes(':')) {
        if (ipFields.ipv6) ipFields.ipv6.textContent = data.ip;
      } else {
        if (ipFields.ipv4) ipFields.ipv4.textContent = data.ip;
      }
    }
    if (ipFields.isp) ipFields.isp.textContent = data.isp || '—';
    if (ipFields.asn) ipFields.asn.textContent = data.asn || '—';
    const loc = [data.city, data.country].filter(Boolean).join(', ');
    if (ipFields.location) ipFields.location.textContent = loc || '—';
    if (ipStatus) {
      ipStatus.textContent = 'Established';
      ipStatus.dataset.state = 'ok';
    }
    probeDualStackIps();
  } catch (err) {
    if (ipFields.ipv4) ipFields.ipv4.innerHTML = '<span class="dim">unavailable</span>';
    if (ipFields.ipv6) ipFields.ipv6.innerHTML = '<span class="dim">unavailable</span>';
    if (ipFields.isp) ipFields.isp.innerHTML = '<span class="dim">—</span>';
    if (ipFields.asn) ipFields.asn.innerHTML = '<span class="dim">—</span>';
    if (ipFields.location) ipFields.location.innerHTML = '<span class="dim">—</span>';
    if (ipStatus) {
      ipStatus.textContent = err.code || 'error';
      ipStatus.dataset.state = 'err';
    }
  }
}

export async function probeDualStackIps() {
  const ipFields = {
    ipv4: document.querySelector('[data-field="ipv4"]'),
    ipv6: document.querySelector('[data-field="ipv6"]'),
  };

  fetch('https://api4.ipify.org?format=json', { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json())
    .then((d) => {
      if (d.ip && ipFields.ipv4) ipFields.ipv4.textContent = d.ip;
    })
    .catch(() => {
      if (ipFields.ipv4 && (!ipFields.ipv4.textContent || ipFields.ipv4.textContent === 'Probing…' || ipFields.ipv4.textContent === 'detecting…')) {
        ipFields.ipv4.innerHTML = '<span class="dim">—</span>';
      }
    });

  fetch('https://api6.ipify.org?format=json', { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json())
    .then((d) => {
      if (d.ip && ipFields.ipv6) ipFields.ipv6.textContent = d.ip;
    })
    .catch(() => {
      if (ipFields.ipv6 && (!ipFields.ipv6.textContent || ipFields.ipv6.textContent === 'Probing…' || ipFields.ipv6.textContent === 'detecting…')) {
        ipFields.ipv6.innerHTML = '<span class="dim">No IPv6 route (IPv4-only egress)</span>';
      }
    });
}

export function initIpCard() {
  const ipCard = document.querySelector('.ip-card');
  if (!ipCard) return;

  const collapseButton = ipCard.querySelector('.collapse-btn');
  const storedCollapsed = localStorage.getItem(LS_KEYS.ipCollapsed);
  const isInitialCollapsed = storedCollapsed === 'true';
  ipCard.dataset.collapsed = String(isInitialCollapsed);
  document.documentElement.dataset.ipCollapsed = String(isInitialCollapsed);

  if (collapseButton) {
    collapseButton.addEventListener('click', () => {
      const isCollapsed = document.documentElement.dataset.ipCollapsed === 'true' || ipCard.dataset.collapsed === 'true';
      const nextCollapsed = !isCollapsed;
      ipCard.dataset.collapsed = String(nextCollapsed);
      document.documentElement.dataset.ipCollapsed = String(nextCollapsed);
      localStorage.setItem(LS_KEYS.ipCollapsed, String(nextCollapsed));
    });
  }

  loadIp();
}
