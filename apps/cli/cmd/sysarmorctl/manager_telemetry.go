package main

import (
	"fmt"
	"net/url"
)

func queryManagerTelemetryAPI(base string, args []string) ([]byte, error) {
	switch args[0] {
	case "metrics":
		return httpGet(base + "/api/v1/metrics")
	case "store-status":
		return httpGet(base + "/api/v1/store-status")
	case "rarity-baseline":
		q := url.Values{}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--workload":
				i++
				if i < len(args) {
					q.Set("workload", args[i])
				}
			case "--signal":
				i++
				if i < len(args) {
					q.Set("signal", args[i])
				}
			}
		}
		return httpGet(base + "/api/v1/rarity-baseline?" + q.Encode())
	case "events":
		q := url.Values{}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--label":
				i++
				if i < len(args) {
					addLabelQuery(q, args[i])
				}
			case "--behavior":
				i++
				if i < len(args) {
					q.Set("behavior", args[i])
				}
			case "--limit":
				i++
				if i < len(args) {
					q.Set("limit", args[i])
				}
			case "--offset":
				i++
				if i < len(args) {
					q.Set("offset", args[i])
				}
			}
		}
		return httpGet(base + "/api/v1/events?" + q.Encode())
	case "signals":
		q := url.Values{}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--label":
				i++
				if i < len(args) {
					addLabelQuery(q, args[i])
				}
			case "--layer":
				i++
				if i < len(args) {
					q.Set("layer", args[i])
				}
			case "--stage":
				i++
				if i < len(args) {
					q.Set("stage", args[i])
				}
			case "--limit":
				i++
				if i < len(args) {
					q.Set("limit", args[i])
				}
			case "--offset":
				i++
				if i < len(args) {
					q.Set("offset", args[i])
				}
			}
		}
		return httpGet(base + "/api/v1/signals?" + q.Encode())
	case "recompute":
		q := url.Values{}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--label":
				i++
				if i < len(args) {
					addLabelQuery(q, args[i])
				}
			case "--disable":
				i++
				if i < len(args) {
					q.Set("disable", args[i])
				}
			case "--mode":
				i++
				if i < len(args) {
					q.Set("mode", args[i])
				}
			case "--tenant-id":
				i++
				if i < len(args) {
					q.Set("tenant_id", args[i])
				}
			case "--agent-id":
				i++
				if i < len(args) {
					q.Set("agent_id", args[i])
				}
			case "--scope-type":
				i++
				if i < len(args) {
					q.Set("scope_type", args[i])
				}
			case "--scope-selector":
				i++
				if i < len(args) {
					q.Set("scope_selector", args[i])
				}
			}
		}
		return httpGet(base + "/api/v1/recompute?" + q.Encode())
	default:
		return nil, fmt.Errorf("unknown command %q", args[0])
	}
}
