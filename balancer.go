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
	ipvs  ipvs.Client
	ipset string
	link  netlink.Link
}

type ipport struct {
	ip   IP4
	port uint16
}

func New(ipset string) (*balancer, error) {
	vs, err := ipvs.New()

	if err != nil {
		return nil, err
	}

	if ipset != "" {
		ipsetgo.Flush(ipset)
	}

	link, err := netlink.LinkByName("ipvs")
	if err != nil {
		return nil, err
	}

	return &balancer{
		ipvs:  vs,
		ipset: ipset,
		link:  link,
	}, nil
}

func (b *balancer) _Configure(h vc5.Healthchecks) {
	println("CONFIGURE")

	if false {
		j, _ := json.MarshalIndent(&h, "", "    ")
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

	for vip, virtual := range h.Virtual {
		for l4, service := range virtual.Services {

			proto := ipvs.TCP

			if l4.Protocol {
				proto = ipvs.UDP
			}

			if b.ipset != "" {

				p := uint8(proto)

				ipsetgo.Add(b.ipset, &ipsetgo.Entry{
					IP:       net.IPv4(vip[0], vip[1], vip[2], vip[3]),
					Protocol: &p,
					Port:     &l4.Port,
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

			if false {
				fmt.Println(vip, l4, service.Healthy)
			}

			svc := ipvs.Service{
				Address:   netip.AddrFrom4(vip),
				Netmask:   netmask.MaskFrom4([4]byte{255, 255, 255, 255}),
				Scheduler: "wrr",
				Port:      l4.Port,
				Family:    ipvs.INET,
				Protocol:  proto,
				Flags:     ipvs.ServiceHashed,
			}

			bar := serv{ip: vip, port: l4.Port, protocol: uint16(proto)}

			if s, ok := existing[bar]; ok {

				if s != svc {

					log.Println("Service needs updating in IPVS:", vip, l4, s, svc)

					err = b.ipvs.UpdateService(svc)

					if err != nil {
						log.Println("failed updating Service in IPVS", err)
					}
				}

			} else {

				log.Println("Creating Service in IPVS:", vip, l4)

				err = b.ipvs.CreateService(svc)

				if err != nil {
					log.Println("failed creating Service in IPVS", err)
				}
			}

			reals := map[ipport]bool{}

			//for k, v := range service.Reals {
			//	reals[ipport{ip: k, port: v.Port}] = v.Probe.Passed
			//}
			for _, v := range service.Destinations() {
				reals[ipport{ip: v.Address, port: v.Port}] = v.Up
			}

			b.destinations(svc, reals)

			delete(existing, bar)

		}
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

		ipConfig := &netlink.Addr{IPNet: &net.IPNet{
			IP:   ip4,
			Mask: net.CIDRMask(32, 32),
		}}

		netlink.AddrDel(b.link, ipConfig)

		if err = b.ipvs.RemoveService(svc); err != nil {
			log.Println("failed removing Service in IPVS", err)
		}
	}

}

func (f *balancer) destinations(svc ipvs.Service, reals map[ipport]bool) {

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
			FwdMethod: ipvs.Masquarade,
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

func (f *balancer) Close() {
}

/********************************************************************************/
func (f *balancer) Stats(h vc5.Healthchecks) map[vc5.Target]vc5.Counter {

	vs := map[string]vc5.Counter{}
	ret := map[vc5.Target]vc5.Counter{}

	services, err := f.ipvs.Services()

	if err != nil {
		return ret
	}

	for _, svc := range services {
		switch svc.Protocol {
		case ipvs.TCP:
		case ipvs.UDP:
		default:
			continue
		}

		s := svc.Service

		dests, _ := f.ipvs.Destinations(s)

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

	// for vip, virtual := range h.Virtual {
	// 	for l4, service := range virtual.Services {
	// 		for rip, _ := range service.Reals {

	// 			proto := ipvs.TCP

	// 			if l4.Protocol {
	// 				proto = ipvs.UDP
	// 			}

	// 			addr := fmt.Sprintf("%s:%d:%s:%s", vip, l4.Port, proto, rip)

	// 			if c, ok := vs[addr]; ok {
	// 				t := Target{VIP: vip, RIP: rip, Port: l4.Port, Protocol: l4.Protocol.Number()}
	// 				ret[t] = c
	// 			}

	// 		}
	// 	}
	// }

	//for vip, virtual := range h.Virtual {
	//	for l4, service := range virtual.Services {
	for svc, service := range h.Services() {
		vip := svc.VIP
		l4 := svc.L4()
		for rip, _ := range service.Reals_() {

			proto := ipvs.TCP

			if l4.Protocol {
				proto = ipvs.UDP
			}

			addr := fmt.Sprintf("%s:%d:%s:%s", vip, l4.Port, proto, rip)

			if c, ok := vs[addr]; ok {
				t := Target{VIP: vip, RIP: rip, Port: l4.Port, Protocol: l4.Protocol.Number()}
				ret[t] = c
			}

		}
		//}
	}

	return ret
}

func (b *balancer) Configure(h vc5.Healthchecks) {
	println("CONFIGURE2")

	if false {
		j, _ := json.MarshalIndent(&h, "", "    ")
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

	for _, service := range h.Services() {
		vip := service.VIP
		udp := service.UDP
		port := service.Port

		proto := ipvs.TCP

		if udp {
			proto = ipvs.UDP
		}

		if b.ipset != "" {

			p := uint8(proto)

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

		if false {
			fmt.Println(vip, port, service.UDP, service.Healthy)
		}

		svc := ipvs.Service{
			Address:   netip.AddrFrom4(vip),
			Netmask:   netmask.MaskFrom4([4]byte{255, 255, 255, 255}),
			Scheduler: "wrr",
			Port:      port,
			Family:    ipvs.INET,
			Protocol:  proto,
			Flags:     ipvs.ServiceHashed,
		}

		bar := serv{ip: vip, port: port, protocol: uint16(proto)}

		if s, ok := existing[bar]; ok {

			if s != svc {

				log.Println("Service needs updating in IPVS:", vip, port, udp, s, svc)

				err = b.ipvs.UpdateService(svc)

				if err != nil {
					log.Println("failed updating Service in IPVS", err)
				}
			}

		} else {

			log.Println("Creating Service in IPVS:", vip, port, udp)

			err = b.ipvs.CreateService(svc)

			if err != nil {
				log.Println("failed creating Service in IPVS", err)
			}
		}

		reals := map[ipport]bool{}

		//for k, v := range service.Reals {
		//	reals[ipport{ip: k, port: v.Port}] = v.Probe.Passed
		//}
		for _, v := range service.Destinations() {
			reals[ipport{ip: v.Address, port: v.Port}] = v.Up
		}

		b.destinations(svc, reals)

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

		ipConfig := &netlink.Addr{IPNet: &net.IPNet{
			IP:   ip4,
			Mask: net.CIDRMask(32, 32),
		}}

		netlink.AddrDel(b.link, ipConfig)

		if err = b.ipvs.RemoveService(svc); err != nil {
			log.Println("failed removing Service in IPVS", err)
		}
	}

}
