package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/davidcoles/vc5"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
	ipsetgo "github.com/lrh3321/ipset-go"
	"github.com/vishvananda/netlink"
)

type balancer struct {
	ipvs   ipvs.Client
	ipset  string
	link   netlink.Link
	config *vc5.Healthchecks
	probes *vc5.Probes
}

type ipport struct {
	ip   IP4
	port uint16
}

func New(ipset, iface string) (*balancer, error) {
	vs, err := ipvs.New()

	if err != nil {
		return nil, err
	}

	if ipset != "" {
		ipsetgo.Flush(ipset)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}

	return &balancer{
		ipvs:  vs,
		ipset: ipset,
		link:  link,
	}, nil
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
			//FwdMethod: ipvs.Tunnel,
			Weight: weight,
			Port:   k.port,
			Family: ipvs.INET,
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

func (f *balancer) Close() {
}

func (b *balancer) Status() vc5.Healthchecks {
	r := b.config.DeepCopy()
	return *r
}

/********************************************************************************/
//func (b *balancer) Stats(h vc5.Healthchecks) (vc5.Counter, map[vc5.Target]vc5.Counter) {
func (b *balancer) Stats() (vc5.Counter, map[vc5.Target]vc5.Counter) {

	var global vc5.Counter

	vs := map[string]vc5.Counter{}
	ret := map[vc5.Target]vc5.Counter{}

	services, err := b.ipvs.Services()

	if err != nil {
		return global, ret
	}

	for _, svc := range services {
		switch svc.Protocol {
		case ipvs.TCP:
		case ipvs.UDP:
		default:
			continue
		}

		s := svc.Service

		dests, _ := b.ipvs.Destinations(s)

		for _, dst := range dests {

			d := dst.Destination

			addr := fmt.Sprintf("%s:%d:%s:%s", s.Address, s.Port, s.Protocol, d.Address)

			c := dst.Stats64

			vs[addr] = vc5.Counter{
				//Concurrent: c.Connections,
				Octets:  c.OutgoingBytes,
				Packets: c.OutgoingPackets,
				//Octets:  c.IncomingBytes,
				//Packets: c.IncomingPackets,
			}

			/*
			   type Counter struct {
			       Octets      uint64
			       Packets     uint64
			       Flows       uint64
			       Concurrent  uint64
			       Blocked     uint64
			       Latency     uint64 // global only
			       QueueFailed uint64 // global only
			       DEFCON      uint8  // global only
			   }
			*/
		}
	}

	for svc, service := range b.config.Services__() {
		vip := svc.VIP
		l4 := svc.L4()
		for _, real := range service.Reals() {
			rip := real.RIP

			proto := ipvs.TCP

			if l4.Protocol {
				proto = ipvs.UDP
			}

			addr := fmt.Sprintf("%s:%d:%s:%s", vip, l4.Port, proto, rip)

			if c, ok := vs[addr]; ok {
				t := Target{VIP: vip, RIP: rip, Port: l4.Port, Protocol: l4.Protocol.Number()}
				ret[t] = c
				global.Add(c)
			}

		}
		//}
	}

	return global, ret
}

func (b *balancer) Start(ip string, hc *vc5.Healthchecks) error {
	b.probes = &vc5.Probes{}
	b.probes.Start(ip)
	b.Configure(hc)
	return nil
}

func (b *balancer) Checker() vc5.Checker {
	//return &checker{socket: v.Socket}
	return b.probes
}

func (b *balancer) Configure(x *vc5.Healthchecks) {
	println("CONFIGURE")

	b.config = x

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

	services, err := b.ipvs.Services()

	for _, svc := range services {
		if svc.Address.Is4() {
			existing[serv{ip: svc.Address.As4(), port: svc.Port, protocol: uint16(svc.Protocol)}] = svc.Service
		}
	}

	//for _, service := range b.config.Services__() {
	services_, _ := b.config.Services()
	for _, service := range services_ {
		vip := service.Address
		port := service.Port

		protocol := ipvs.Protocol(service.Protocol)

		if b.ipset != "" {

			p := uint8(protocol)

			ipsetgo.Add(b.ipset, &ipsetgo.Entry{
				IP:       net.IPv4(vip[0], vip[1], vip[2], vip[3]),
				Protocol: &p,
				Port:     &port,
			})
		}

		ipConfig := &netlink.Addr{IPNet: &net.IPNet{
			IP:   net.IPv4(vip[0], vip[1], vip[2], vip[3]), //net.ParseIP("192.168.0.2"),
			Mask: net.CIDRMask(32, 32),
		}}

		netlink.AddrAdd(b.link, ipConfig)
		//if err = netlink.AddrAdd(b.link, ipConfig); err != nil {
		//	log.Fatal(err)
		//}

		//var sched vc5.Scheduler = vc5.WLC //= vc5.WRR
		//var sticky bool = false

		sched := service.Scheduler
		sticky := service.Sticky

		fmt.Println(sched.String())

		name, flags := IPVS(sched, sticky)

		svc := ipvs.Service{
			Address:  netip.AddrFrom4(vip),
			Netmask:  netmask.MaskFrom4([4]byte{255, 255, 255, 255}),
			Family:   ipvs.INET,
			Protocol: protocol,
			Port:     port,

			Scheduler: name,
			Flags:     flags,
		}

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

		//for _, v := range service.Destinations() {
		destinations, _ := b.config.Destinations(service)
		for _, v := range destinations {
			reals[ipport{ip: v.Address, port: v.Port}] = v.Up
		}

		ft := ipvs.Masquarade
		//ft := ipvs.DirectRoute
		//ft := ipvs.Tunnel

		b.destinations(svc, ft, reals)

		delete(existing, bar)

	}

	for _, svc := range existing {

		as4 := svc.Address.As4()
		ip4 := net.IPv4(as4[0], as4[1], as4[2], as4[3])

		if b.ipset != "" {
			p := uint8(svc.Protocol)

			ipsetgo.Del(b.ipset, &ipsetgo.Entry{
				IP:       ip4,
				Protocol: &p,
				Port:     &svc.Port,
			})
		}

		//ipConfig := &netlink.Addr{IPNet: &net.IPNet{
		//	IP:   ip4,
		//	Mask: net.CIDRMask(32, 32),
		//}}
		//netlink.AddrDel(b.link, ipConfig)

		if err = b.ipvs.RemoveService(svc); err != nil {
			log.Println("failed removing Service in IPVS", err)
		}
	}
}

func IPVS(s vc5.Scheduler, sticky bool) (string, ipvs.Flags) {
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
