package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
)

func PingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		baseTargetRequest
		Count int `json:"count"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	count := req.Count
	if count <= 0 {
		count = 10
	} else if count > 10 {
		count = 10
	}

	payload := map[string]any{
		"target": target,
		"type":   "ping",
		"limit":  1,
		"measurementOptions": map[string]any{
			"packets": count,
		},
	}
	if locs := engine.BuildLocations(req.Location); locs != nil {
		payload["locations"] = locs
	}

	resBytes, err := engine.RunMeasurement(r.Context(), payload)
	if err != nil {
		HandleError(w, err)
		return
	}

	var gpRes struct {
		Results []struct {
			Result struct {
				Stats struct {
					Total any `json:"total"`
					Rcv   any `json:"rcv"`
					Loss  any `json:"loss"`
					Min   any `json:"min"`
					Avg   any `json:"avg"`
					Max   any `json:"max"`
				} `json:"stats"`
				RawOutput string `json:"rawOutput"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resBytes, &gpRes); err != nil {
		JSONError(w, http.StatusBadGateway, "Invalid response from upstream probe")
		return
	}

	sent := 0
	recv := 0
	lossPct := 100.0
	minRTT, avgRTT, maxRTT := 0.0, 0.0, 0.0
	raw := "no probe results"

	if len(gpRes.Results) > 0 {
		res := gpRes.Results[0].Result
		raw = strings.TrimSpace(res.RawOutput)
		sent = toInt(res.Stats.Total)
		recv = toInt(res.Stats.Rcv)
		if res.Stats.Loss != nil {
			lossPct = toFloat(res.Stats.Loss)
		} else if sent > 0 {
			lossPct = float64(sent-recv) / float64(sent) * 100.0
		}
		minRTT = toFloat(res.Stats.Min)
		avgRTT = toFloat(res.Stats.Avg)
		maxRTT = toFloat(res.Stats.Max)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host":         target,
		"packets_sent": sent,
		"packets_recv": recv,
		"loss_pct":     lossPct,
		"min":          minRTT,
		"avg":          avgRTT,
		"max":          maxRTT,
		"raw":          raw,
	})
}

func TracerouteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		baseTargetRequest
		MaxHops int `json:"max_hops"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	payload := map[string]any{
		"target": target,
		"type":   "traceroute",
		"limit":  1,
		"measurementOptions": map[string]any{
			"protocol": "ICMP",
		},
	}
	if locs := engine.BuildLocations(req.Location); locs != nil {
		payload["locations"] = locs
	}

	resBytes, err := engine.RunMeasurement(r.Context(), payload)
	if err != nil {
		HandleError(w, err)
		return
	}

	var gpRes struct {
		Results []struct {
			Result struct {
				Hops []struct {
					ResolvedAddress  *string `json:"resolvedAddress"`
					ResolvedHostname *string `json:"resolvedHostname"`
					Timings          []struct {
						RTT any `json:"rtt"`
					} `json:"timings"`
				} `json:"hops"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resBytes, &gpRes); err != nil {
		JSONError(w, http.StatusBadGateway, "Invalid response from upstream probe")
		return
	}

	type HopOut struct {
		N         int      `json:"n"`
		IP        *string  `json:"ip"`
		Hostname  *string  `json:"hostname"`
		LatencyMS *float64 `json:"latency_ms"`
	}

	var hops []HopOut
	if len(gpRes.Results) > 0 {
		for i, h := range gpRes.Results[0].Result.Hops {
			var bestRTT *float64
			for _, t := range h.Timings {
				if t.RTT != nil {
					v := toFloat(t.RTT)
					if bestRTT == nil || v < *bestRTT {
						bestRTT = &v
					}
				}
			}
			hostname := h.ResolvedHostname
			if hostname != nil && h.ResolvedAddress != nil && *hostname == *h.ResolvedAddress {
				hostname = nil
			}
			hops = append(hops, HopOut{
				N:         i + 1,
				IP:        h.ResolvedAddress,
				Hostname:  hostname,
				LatencyMS: bestRTT,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"hops": hops})
}

func MtrHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req baseTargetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	payload := map[string]any{
		"target": target,
		"type":   "mtr",
		"limit":  1,
		"measurementOptions": map[string]any{
			"protocol": "ICMP",
			"packets":  10,
		},
	}
	if locs := engine.BuildLocations(req.Location); locs != nil {
		payload["locations"] = locs
	}

	resBytes, err := engine.RunMeasurement(r.Context(), payload)
	if err != nil {
		HandleError(w, err)
		return
	}

	var gpRes struct {
		Results []struct {
			Result struct {
				Hops []struct {
					ResolvedAddress  *string `json:"resolvedAddress"`
					ResolvedHostname *string `json:"resolvedHostname"`
					Stats            struct {
						Total any `json:"total"`
						Rcv   any `json:"rcv"`
						Loss  any `json:"loss"`
						Min   any `json:"min"`
						Avg   any `json:"avg"`
						Max   any `json:"max"`
					} `json:"stats"`
				} `json:"hops"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resBytes, &gpRes); err != nil {
		JSONError(w, http.StatusBadGateway, "Invalid response from upstream probe")
		return
	}

	type MtrHopOut struct {
		N        int      `json:"n"`
		IP       *string  `json:"ip"`
		Hostname *string  `json:"hostname"`
		LossPct  float64  `json:"loss_pct"`
		AvgMS    *float64 `json:"avg_ms"`
		BestMS   *float64 `json:"best_ms"`
		WorstMS  *float64 `json:"worst_ms"`
	}

	var hops []MtrHopOut
	if len(gpRes.Results) > 0 {
		for i, h := range gpRes.Results[0].Result.Hops {
			sent := toInt(h.Stats.Total)
			recv := toInt(h.Stats.Rcv)
			loss := 0.0
			if h.Stats.Loss != nil {
				loss = toFloat(h.Stats.Loss)
			} else if sent > 0 {
				loss = float64(sent-recv) / float64(sent) * 100.0
			}

			var avg, best, worst *float64
			if h.Stats.Avg != nil {
				v := toFloat(h.Stats.Avg)
				avg = &v
			}
			if h.Stats.Min != nil {
				v := toFloat(h.Stats.Min)
				best = &v
			}
			if h.Stats.Max != nil {
				v := toFloat(h.Stats.Max)
				worst = &v
			}

			hostname := h.ResolvedHostname
			if hostname != nil && h.ResolvedAddress != nil && *hostname == *h.ResolvedAddress {
				hostname = nil
			}

			hops = append(hops, MtrHopOut{
				N:        i + 1,
				IP:       h.ResolvedAddress,
				Hostname: hostname,
				LossPct:  loss,
				AvgMS:    avg,
				BestMS:   best,
				WorstMS:  worst,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host": target,
		"hops": hops,
	})
}
