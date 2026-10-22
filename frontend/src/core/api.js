/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

import { LS_KEYS } from '../config.js';
import { state } from './state.js';

export async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  const token = localStorage.getItem(LS_KEYS.token);
  if (token) headers.Authorization = `Bearer ${token}`;

  const opts = {
    ...options,
    headers: { ...headers, ...(options.headers || {}) },
    signal: options.signal || (state.currentAbortController ? state.currentAbortController.signal : undefined),
  };

  let resp;
  try {
    resp = await fetch(path, opts);
  } catch (err) {
    if (err.name === 'AbortError') {
      const abortErr = new Error('Probe cancelled by operator');
      abortErr.code = 'cancelled';
      abortErr.isAbort = true;
      throw abortErr;
    }
    throw err;
  }

  let body = null;
  try {
    body = await resp.json();
  } catch {
    /* non-json */
  }

  if (!resp.ok) {
    const err = new Error(
      (body && (body.message || body.detail)) ||
      `HTTP Error ${resp.status}: Request failed while communicating with server.`
    );
    err.status = resp.status;
    err.code = (body && body.error) || (resp.status === 404 ? 'not_found' : 'http_error');
    if (resp.status === 401 || resp.status === 403) {
      if (!body || !body.error) err.code = resp.status === 401 ? 'unauthorized' : 'forbidden';
      if (!body || !body.message) {
        err.message = resp.status === 401
          ? 'Authentication Required (HTTP 401): Valid bearer token required in Authorization header.'
          : 'Access Forbidden (HTTP 403): Operation rejected by server policy.';
      }
    }
    throw err;
  }

  return body;
}
