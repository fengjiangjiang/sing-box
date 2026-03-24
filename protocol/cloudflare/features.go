//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"net"
	"time"
)

const (
	featureSelectorHostname = "cfd-features.argotunnel.com"
	featureLookupTimeout    = 10 * time.Second
)

type cloudflaredFeaturesRecord struct {
	DatagramV3Percentage uint32 `json:"dv3_2"`
}

var lookupCloudflaredFeatures = func(ctx context.Context) ([]byte, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, featureLookupTimeout)
	defer cancel()

	records, err := net.DefaultResolver.LookupTXT(lookupCtx, featureSelectorHostname)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return []byte(records[0]), nil
}

func resolveDatagramVersion(ctx context.Context, accountTag string, configured string) string {
	if configured != "" {
		return configured
	}
	record, err := lookupCloudflaredFeatures(ctx)
	if err != nil {
		return "v2"
	}

	var features cloudflaredFeaturesRecord
	if err := json.Unmarshal(record, &features); err != nil {
		return "v2"
	}
	if accountEnabled(accountTag, features.DatagramV3Percentage) {
		return "v3"
	}
	return "v2"
}

func accountEnabled(accountTag string, percentage uint32) bool {
	if percentage == 0 {
		return false
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(accountTag))
	return percentage > hasher.Sum32()%100
}
