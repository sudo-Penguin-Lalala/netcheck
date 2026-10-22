/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

export const LS_KEYS = {
  theme: 'nc.theme.v1',
  token: 'nc.token.v1',
  history: 'nc.history.v1',
  tab: 'nc.tab.v1',
  ipCollapsed: 'nc.ip_collapsed.v1',
  historyCollapsed: 'nc.history_collapsed.v1',
};

export const TAB_KEY_MAP = {
  p: 'ping',
  d: 'dns',
  t: 'traceroute',
  m: 'mtr',
  o: 'port',
  r: 'rdns',
  w: 'whois',
  h: 'headers',
  s: 'ssl',
  i: 'ip-lookup',
  x: 'http',
};

export const TOOL_LABELS = {
  dns: 'DNS lookup',
  ping: 'Ping',
  traceroute: 'Traceroute',
  mtr: 'MTR',
  port: 'Port check',
  rdns: 'Reverse DNS',
  whois: 'WHOIS',
  headers: 'Request headers',
  ssl: 'SSL certificate',
  'ip-lookup': 'IP lookup',
  http: 'HTTP request',
};

export function toolLabel(tool) {
  return TOOL_LABELS[tool] || tool;
}
