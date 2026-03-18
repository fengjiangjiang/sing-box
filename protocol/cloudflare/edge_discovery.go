//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	edgeSRVService = "v2-origintunneld"
	edgeSRVProto   = "tcp"
	edgeSRVName    = "argotunnel.com"

	dotServerName = "cloudflare-dns.com"
	dotServerAddr = "1.1.1.1:853"
	dotTimeout    = 15 * time.Second
)

// EdgeAddr represents a Cloudflare edge server address.
type EdgeAddr struct {
	TCP       *net.TCPAddr
	UDP       *net.UDPAddr
	IPVersion int // 4 or 6
}

// DiscoverEdge performs SRV-based edge discovery and returns addresses
// partitioned into regions (typically 2).
func DiscoverEdge(ctx context.Context) ([][]*EdgeAddr, error) {
	regions, err := lookupEdgeSRV()
	if err != nil {
		regions, err = lookupEdgeSRVWithDoT(ctx)
		if err != nil {
			return nil, E.Cause(err, "edge discovery")
		}
	}
	if len(regions) == 0 {
		return nil, E.New("edge discovery: no edge addresses found")
	}
	return regions, nil
}

func lookupEdgeSRV() ([][]*EdgeAddr, error) {
	_, addrs, err := net.LookupSRV(edgeSRVService, edgeSRVProto, edgeSRVName)
	if err != nil {
		return nil, err
	}
	return resolveSRVRecords(addrs)
}

func lookupEdgeSRVWithDoT(ctx context.Context) ([][]*EdgeAddr, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", dotServerAddr)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, &tls.Config{ServerName: dotServerName}), nil
		},
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dotTimeout)
	defer cancel()
	_, addrs, err := resolver.LookupSRV(lookupCtx, edgeSRVService, edgeSRVProto, edgeSRVName)
	if err != nil {
		return nil, err
	}
	return resolveSRVRecords(addrs)
}

func resolveSRVRecords(records []*net.SRV) ([][]*EdgeAddr, error) {
	var regions [][]*EdgeAddr
	for _, record := range records {
		ips, err := net.LookupIP(record.Target)
		if err != nil {
			return nil, E.Cause(err, "resolve SRV target: ", record.Target)
		}
		if len(ips) == 0 {
			continue
		}
		edgeAddrs := make([]*EdgeAddr, 0, len(ips))
		for _, ip := range ips {
			ipVersion := 6
			if ip.To4() != nil {
				ipVersion = 4
			}
			edgeAddrs = append(edgeAddrs, &EdgeAddr{
				TCP:       &net.TCPAddr{IP: ip, Port: int(record.Port)},
				UDP:       &net.UDPAddr{IP: ip, Port: int(record.Port)},
				IPVersion: ipVersion,
			})
		}
		regions = append(regions, edgeAddrs)
	}
	return regions, nil
}

// FilterByIPVersion filters edge addresses to only include the specified IP version.
// version 0 means no filtering (auto).
func FilterByIPVersion(regions [][]*EdgeAddr, version int) [][]*EdgeAddr {
	if version == 0 {
		return regions
	}
	var filtered [][]*EdgeAddr
	for _, region := range regions {
		var addrs []*EdgeAddr
		for _, addr := range region {
			if addr.IPVersion == version {
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) > 0 {
			filtered = append(filtered, addrs)
		}
	}
	return filtered
}
