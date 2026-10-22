/*
 * Copyright (c) 2026 NNT
 * This file is part of NetCheck.
 * AGPL-3.0 License
 */

let _currentAbortController = null;
let _lastTelemetryPayload = null;
let _lastRawTelemetry = '';
let _lastResultText = '';
let _loadingTimer = null;

export const state = {
  get currentAbortController() {
    return _currentAbortController;
  },
  set currentAbortController(val) {
    _currentAbortController = val;
  },

  get lastTelemetryPayload() {
    return _lastTelemetryPayload;
  },
  set lastTelemetryPayload(val) {
    _lastTelemetryPayload = val;
  },

  get lastRawTelemetry() {
    return _lastRawTelemetry;
  },
  set lastRawTelemetry(val) {
    _lastRawTelemetry = val;
  },

  get lastResultText() {
    return _lastResultText;
  },
  set lastResultText(val) {
    _lastResultText = val;
  },

  get loadingTimer() {
    return _loadingTimer;
  },
  set loadingTimer(val) {
    _loadingTimer = val;
  },

  abortCurrentProbe(reason = 'aborted') {
    if (_currentAbortController) {
      _currentAbortController.abort();
      _currentAbortController = null;
    }
    if (_loadingTimer) {
      clearInterval(_loadingTimer);
      _loadingTimer = null;
    }
    document.querySelectorAll('.run-btn[aria-busy="true"]').forEach((b) => b.removeAttribute('aria-busy'));
    const resultSection = document.querySelector('.result-section');
    if (resultSection) {
      resultSection.setAttribute('aria-busy', 'false');
    }
  },
};
