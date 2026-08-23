package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"gopkg.in/yaml.v3"
)

// Config is the YAML configuration file.
type Config struct {
	UpstreamAddrs []string          `yaml:"upstream_addrs"`
	ListenAddrs   listenAddrsConfig `yaml:"listen_addrs"`
}

// listenAddrsConfig is the configuration of the server listenning addrs for
// different protocols.
//
// TODO: Add encrypted protocols.
type listenAddrsConfig struct {
	UDP []netip.AddrPort `yaml:"udp"`
	TCP []netip.AddrPort `yaml:"tcp"`
}

// parseConfig parses config file.
func parseConfig(path string) (c *Config, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}

	c = &Config{}
	err = yaml.NewDecoder(file).Decode(c)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return c, nil
}

// upstreamsToInternal converts slice of upstream addrs to slice of
// upstream.Upstream.
func upstreamsToInternal(addr []string) (upstreams []upstream.Upstream, err error) {
	for _, addr := range addr {
		var up upstream.Upstream
		up, err = upstream.NewUpstreamResolver(addr, nil)
		if err != nil {
			return nil, fmt.Errorf("creating upstream resolver for addr: %s: %w", addr, err)
		}

		upstreams = append(upstreams, up)
	}

	return upstreams, nil
}

// listenAddrs is the internal representation of [listenAddrsConfig]
type listenAddrs struct {
	UDP []*net.UDPAddr
	TCP []*net.TCPAddr
}

// toInternal converts listenAddrsConfig to listenAddrs.
func (c *listenAddrsConfig) toInternal() (l *listenAddrs) {
	l = &listenAddrs{}

	for _, u := range c.UDP {
		l.UDP = append(l.UDP, net.UDPAddrFromAddrPort(u))
	}

	for _, t := range c.TCP {
		l.TCP = append(l.TCP, net.TCPAddrFromAddrPort(t))
	}

	return l
}
