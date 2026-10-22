/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

export function latencyBand(ms) {
  if (ms == null || isNaN(ms)) return 'high';
  if (ms < 50) return 'low';
  if (ms <= 150) return 'mid';
  return 'high';
}

export function formatLatency(ms) {
  if (ms == null) return '<span class="dim">—</span>';
  const band = latencyBand(ms);
  const val = typeof ms === 'number' ? ms.toFixed(1) : ms;
  return `<span class="latency-val" data-latency-band="${band}">${val} ms</span>`;
}
