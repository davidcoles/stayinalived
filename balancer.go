package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/davidcoles/vc5"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
	"github.com/lrh3321/ipset-go"
	"github.com/vishvananda/netlink"
)

type balancer struct {
	ipvs   ipvs.Client
	ipset  string
	link   netlink.Link
	config *vc5.Healthchecks
	probes *vc5.Probes
	mutex  sync.Mutex
	vips   map[IP4]bool
	done   chan bool
}

type ipport struct {
	ip   IP4
	port uint16
}

func New(set, iface string) (*balancer, error) {
	vs, err := ipvs.New()

	if err != nil {
		return nil, err
	}

	if set != "" {
		ipset.Flush(set)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}

	return &balancer{
		ipvs:  vs,
		ipset: set,
		link:  link,
	}, nil
}

func (b *balancer) Close() {
	//close(b.c)
	close(b.done)
}

func (b *balancer) Status() vc5.Healthchecks {
	r := b.config.DeepCopy()
	return *r
}

func (b *balancer) Start(ip string, hc *vc5.Healthchecks) error {
	b.done = make(chan bool)
	b.vips = map[IP4]bool{}
	b.probes = &vc5.Probes{}
	b.probes.Start(ip)
	b.Configure(hc)
	go b.background(b.done)
	return nil
}

func (b *balancer) Checker() vc5.Checker {
	return b.probes
}

func (b *balancer) Configure(config *vc5.Healthchecks) {
	b.configure(config)
}

func (b *balancer) background(done chan bool) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C: // preiodically refresh in case VIPs get removed from dummy interface (eg. by netplan apply)
			b.mutex.Lock()
			config := b.config // re-use current config
			b.mutex.Unlock()
			b.configure(config)
		case <-b.done:
			return
		}
	}
}

/********************************************************************************/

func (b *balancer) Stats() (vc5.Counter, map[vc5.Target]vc5.Counter) {

	var global vc5.Counter

	vs := map[string]vc5.Counter{}
	ret := map[vc5.Target]vc5.Counter{}

	services, _ := b.ipvs.Services()
	for _, svc := range services {
		s := svc.Service

		destinations, _ := b.ipvs.Destinations(s)
		for _, d := range destinations {

			addr := fmt.Sprintf("%s:%d:%d:%s", s.Address, s.Port, s.Protocol, d.Destination.Address)
			vs[addr] = vc5.Counter{
				Octets:  d.Stats64.OutgoingBytes,
				Packets: d.Stats64.OutgoingPackets,
			}
		}
	}

	services_, _ := b.config.Services()
	for _, s := range services_ {

		destinations, _ := b.config.Destinations(s)
		for _, d := range destinations {

			addr := fmt.Sprintf("%s:%d:%d:%s", s.Address, s.Port, s.Protocol, d.Address)

			if c, ok := vs[addr]; ok {
				t := Target{VIP: s.Address, RIP: d.Address, Port: s.Port, Protocol: s.Protocol}
				ret[t] = c
				global.Add(c)
			}
		}
	}

	return global, ret
}

/********************************************************************************/

func (b *balancer) configure(config *vc5.Healthchecks) {
	println("CONFIGURE")

	b.mutex.Lock()
	defer b.mutex.Unlock()

	vips := map[IP4]bool{}

	b.config = config

	if false {
		j, _ := json.MarshalIndent(b.config, "", "    ")
		fmt.Println(string(j))
	}

	type serv struct {
		ip       IP4
		port     uint16
		protocol uint16
	}

	existing := map[serv]ipvs.Service{}

	ipvsServices, err := b.ipvs.Services()
	for _, svc := range ipvsServices {
		if svc.Address.Is4() {
			existing[serv{ip: svc.Address.As4(), port: svc.Port, protocol: uint16(svc.Protocol)}] = svc.Service
		}
	}

	services, _ := b.config.Services()
	for _, service := range services {
		vip := service.Address
		port := service.Port
		protocol := service.Protocol

		vips[vip] = true

		if b.ipset != "" {
			ipset.Add(b.ipset, ipsetEntry(vip, port, protocol))
		}

		svc := ipvsService(service)

		bar := serv{ip: vip, port: port, protocol: uint16(protocol)}

		if s, ok := existing[bar]; ok {

			x := svc
			x.Flags |= ipvs.ServiceHashed
			s.Flags |= ipvs.ServiceHashed

			if s != x {

				log.Println("Service needs updating in IPVS:", vip, port, protocol, s, svc)

				err = b.ipvs.UpdateService(svc)

				if err != nil {
					log.Println("failed updating Service in IPVS", err)
				}
			}

		} else {

			log.Println("Creating Service in IPVS:", vip, port, protocol)

			err = b.ipvs.CreateService(svc)

			if err != nil {
				log.Println("failed creating Service in IPVS", err)
			}
		}

		reals := map[ipport]bool{}

		destinations, _ := b.config.Destinations(service)
		for _, v := range destinations {
			reals[ipport{ip: v.Address, port: v.Port}] = v.Up
		}

		b.destinations(svc, ipvs.Masquarade, reals) // alternatives: ipvs.DirectRoute, ipvs.Tunnel

		delete(existing, bar)
	}

	for _, svc := range existing {

		if b.ipset != "" {
			ipset.Del(b.ipset, ipsetEntry(svc.Address.As4(), svc.Port, uint8(svc.Protocol)))
		}

		if err = b.ipvs.RemoveService(svc); err != nil {
			log.Println("failed removing Service in IPVS", err)
		}
	}

	// add service IP addresses to interface
	for v, _ := range vips {
		netlink.AddrAdd(b.link, netlinkAddr(v))
		delete(b.vips, v) // ensure address doesn't get removed in next step
	}

	// remove any addresses which are no longer active
	for v, _ := range b.vips {
		netlink.AddrDel(b.link, netlinkAddr(v))
	}

	b.vips = vips
}

func (f *balancer) destinations(svc ipvs.Service, ft ipvs.ForwardType, reals map[ipport]bool) {

	vs := map[string]ipvs.DestinationExtended{}

	dests, err := f.ipvs.Destinations(svc)

	for _, dst := range dests {
		addr := fmt.Sprintf("%s:%d", dst.Address, dst.Port)
		vs[addr] = dst
	}

	for k, v := range reals {
		addr := fmt.Sprintf("%s:%d", k.ip, k.port)

		var weight uint32

		if v {
			weight = 1
		}

		dst := ipvs.Destination{
			Address:   netip.AddrFrom4(k.ip),
			FwdMethod: ft,
			Weight:    weight,
			Port:      k.port,
			Family:    ipvs.INET,
		}

		if d, ok := vs[addr]; ok {

			if d.Destination != dst {
				if err = f.ipvs.UpdateDestination(svc, dst); err != nil {
					log.Println("destination update failed", addr)
				}
			}

		} else {
			if err = f.ipvs.CreateDestination(svc, dst); err != nil {
				log.Println("error creating destination:", addr, err)
			}
		}

		delete(vs, addr)
	}

	for _, dst := range vs {
		f.ipvs.RemoveDestination(svc, dst.Destination)
	}
}

func ipvsService(service vc5.Service) ipvs.Service {
	name, flags := ipvsScheduler(service.Scheduler, service.Sticky)

	return ipvs.Service{
		Address:   netip.AddrFrom4(service.Address),
		Netmask:   netmask.MaskFrom4([4]byte{255, 255, 255, 255}),
		Family:    ipvs.INET,
		Protocol:  ipvs.Protocol(service.Protocol),
		Port:      service.Port,
		Scheduler: name,
		Flags:     flags,
	}

}

func netlinkAddr(i IP4) *netlink.Addr {
	return &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.IPv4(i[0], i[1], i[2], i[3]),
		Mask: net.CIDRMask(32, 32),
	}}
}

func ipsetEntry(ip IP4, port uint16, protocol uint8) *ipset.Entry {
	return &ipset.Entry{
		IP:       net.IPv4(ip[0], ip[1], ip[2], ip[3]),
		Protocol: &protocol,
		Port:     &port,
	}
}

func ipvsScheduler(s vc5.Scheduler, sticky bool) (string, ipvs.Flags) {
	// rr    - Round Robin
	// wrr   - Weighted Round Robin
	// lc    - Least-Connection
	// wlc   - Weighted  Least-Connection
	// lblc  - Locality-Based Least-Connection
	// lblcr - Locality-Based Least-Connection with Replication
	// dh    - Destination Hashing
	// sh    - Source Hashing: sh-fallback, sh-port
	// sed   - Shortest Expected Delay
	// nq    - Never  Queue
	// fo    - Weighted Failover
	// ovf   - Weighted Overflow
	// mh    - Maglev Hashing: mh-fallback, mh-port

	const (
		MH_FALLBACK = ipvs.ServiceSchedulerOpt1
		MH_PORT     = ipvs.ServiceSchedulerOpt2
	)

	var flags ipvs.Flags //= ipvs.ServiceHashed // seems to get set by default

	if sticky {
		flags |= ipvs.ServicePersistent
	}

	switch s {
	case vc5.WRR:
		return "wrr", flags
	case vc5.WLC:
		return "wlc", flags
	case vc5.MH_PORT:
		return "mh", flags | MH_PORT | MH_FALLBACK
	}

	return "wlc", flags
}
