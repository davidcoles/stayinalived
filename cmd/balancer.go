/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lrh3321/ipset-go"
	"github.com/vishvananda/netlink"

	"vc5"
)

type Balancer struct {
	Client Client
	Link   string
	IPSet  string

	link     *netlink.Link
	mutex    sync.Mutex
	state    map[vc5.Service]vc5.Manifest
	maintain chan bool
}

func (b *Balancer) Stats() (vc5.Summary, map[vc5.Instance]vc5.Stats) {

	var summary vc5.Summary
	stats := map[vc5.Instance]vc5.Stats{}
	tcpstats := tcpStats()
	services, _ := b.Client.Services()

	for _, s := range services {
		summary.IngressOctets += s.Stats.IncomingBytes
		summary.IngressPackets += s.Stats.IncomingPackets
		summary.EgressOctets += s.Stats.OutgoingBytes
		summary.EgressPackets += s.Stats.OutgoingPackets
		summary.Flows += s.Stats.Connections

		destinations, _ := b.Client.Destinations(s.Service)
		for _, d := range destinations {

			instance := vc5.Instance{
				Service:     from_ipvs(s.Service),
				Destination: vc5.Destination{Address: d.Destination.Address, Port: d.Destination.Port},
			}

			tcp := tcpstats[instance]
			stats[instance] = vc5.Stats{
				IngressOctets:  d.Stats.IncomingBytes,
				IngressPackets: d.Stats.IncomingPackets,
				EgressOctets:   d.Stats.OutgoingBytes,
				EgressPackets:  d.Stats.OutgoingPackets,
				Flows:          d.Stats.Connections,
				Current:        tcp.ESTABLISHED,
			}
		}
	}

	return summary, stats
}

func (b *Balancer) Configure(services []vc5.Manifest) error {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	vipsToRemove := b._vips()       // old vips todelete if not still required
	todo := mapServices(services)   // services which will need to be configured
	b.state = mapServices(services) // update state for maintance run

	for t, _ := range todo {
		delete(vipsToRemove, t.Address) // don't remove required vips
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {

		if !s.Service.Address.Is4() && !s.Service.Address.Is6() {
			continue
		}

		key := from_ipvs(s.Service)

		if t, wanted := todo[key]; !wanted {

			if err := b.Client.RemoveService(s.Service); err != nil {
				return fmt.Errorf("RemoveService(%s) failed: %s", key, err.Error())
			}

			if e := ipsetEntry(key); e != nil && b.IPSet != "" {
				ipset.Del(b.IPSet, e)
			}

		} else {
			service := ipvsService(t)
			drain := !t.Reset

			if service != s.Service {
				if err := b.Client.UpdateService(service); err != nil {
					return fmt.Errorf("UpdateService(%s) failed: %s", key, err.Error())
				}
			}

			if err := ipvsSyncDestinations(b.Client, s.Service, t.Destinations, drain); err != nil {
				return err
			}

			delete(todo, key) // no need to create as it exists - take off the todo list
		}
	}

	// create any non-existing services
	for key, s := range todo {
		service := ipvsService(s)
		drain := !s.Reset

		if err := b.Client.CreateService(service); err != nil {
			return fmt.Errorf("CreateService(%s) failed: %s", key, err.Error())
		}

		if err := ipvsSyncDestinations(b.Client, service, s.Destinations, drain); err != nil {
			return err
		}
	}

	// remove any addresses which are no longer active
	for v, _ := range vipsToRemove {
		if addr := netlinkAddr(v); b.link != nil && addr != nil {
			netlink.AddrDel(*b.link, netlinkAddr(v))
		}
	}

	// make sure IPs are on link device and ipset is populated
	select {
	case b.maintain <- true:
	default:
	}

	return nil
}

func (b *Balancer) start(ctx context.Context) error {

	if b.Link != "" {
		l, err := netlink.LinkByName(b.Link)
		if err != nil {
			return err
		}
		b.link = &l
	}

	b.maintain = make(chan bool, 1)

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
			case <-b.maintain:
			case <-ctx.Done():
				b._maintain(true)
				return
			}

			b._maintain(false)
		}
	}()

	return nil
}

func (b *Balancer) _vips() map[netip.Addr]bool {
	vips := map[netip.Addr]bool{}

	for t, _ := range b.state {
		vips[t.Address] = true
	}

	return vips
}

// arrange to call every 60 seconds to maintain ipset & vips
func (b *Balancer) _maintain(fin bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	ipset.Create(b.IPSet, "hash:ip,port", ipset.CreateOptions{Timeout: 90, Replace: true})

	if fin {
		for t, _ := range b.state {
			if e := ipsetEntry(t); e != nil && b.IPSet != "" {
				ipset.Del(b.IPSet, e)
			}
		}

		for v, _ := range b._vips() {
			if addr := netlinkAddr(v); b.link != nil && addr != nil {
				netlink.AddrDel(*b.link, netlinkAddr(v))
			}
		}

		return
	}

	for t, _ := range b.state {
		if e := ipsetEntry(t); e != nil && b.IPSet != "" {
			ipset.Add(b.IPSet, e)
		}
	}

	for v, _ := range b._vips() {
		if addr := netlinkAddr(v); b.link != nil && addr != nil {
			netlink.AddrAdd(*b.link, netlinkAddr(v))
		}
	}

}

func ipsetEntry(t vc5.Service) *ipset.Entry {

	var ip net.IP

	if t.Address.Is4() {
		ip4 := t.Address.As4()
		ip = ip4[:]
	} else if t.Address.Is6() {
		ip6 := t.Address.As16()
		ip = ip6[:]
	} else {
		return nil
	}

	protocol := uint8(t.Protocol)

	return &ipset.Entry{IP: ip, Port: &(t.Port), Protocol: &protocol, Replace: true}
}

func netlinkAddr(a netip.Addr) *netlink.Addr {

	if p, err := a.Prefix(a.BitLen()); err == nil {
		if i, err := netlink.ParseAddr(p.String()); err == nil {
			return i
		}
	}

	return nil
}
