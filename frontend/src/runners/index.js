/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { runDns } from './dns.js';
import { runPing } from './ping.js';
import { runTraceroute } from './traceroute.js';
import { runMtr } from './mtr.js';
import { runPort } from './port.js';
import { runRdns } from './rdns.js';
import { runWhois } from './whois.js';
import { runHeaders } from './headers.js';
import { runSsl } from './ssl.js';
import { runIpLookup } from './ip_lookup.js';
import { runHttp } from './http.js';

export const runners = {
  dns: runDns,
  ping: runPing,
  traceroute: runTraceroute,
  mtr: runMtr,
  port: runPort,
  rdns: runRdns,
  whois: runWhois,
  headers: runHeaders,
  ssl: runSsl,
  'ip-lookup': runIpLookup,
  http: runHttp,
};
