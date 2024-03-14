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
	"encoding/json"
	//"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/davidcoles/cue"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
	"github.com/lrh3321/ipset-go"
	"github.com/vishvananda/netlink"
)

type tuple struct {
	addr netip.Addr
	port uint16
	prot uint8
}

type Balancer struct {
	Client ipvs.Client
	Logger Logger
	Link   *netlink.Link
	IPSet  string

	vip map[netip.Addr]bool
}

type Client = ipvs.Client

func NewClient() (ipvs.Client, error) {
	return ipvs.New()
}

// FIXME add background function to maintain IP address and ipset group

// FIXME add logging
func netlinkAddr(a netip.Addr) *netlink.Addr {

	if p, err := a.Prefix(a.BitLen()); err == nil {
		if i, err := netlink.ParseAddr(p.String()); err == nil {
			return i
		}
	}

	return nil
}

func ipsetEntry(s ipvs.Service) *ipset.Entry {

	var ip net.IP

	if s.Address.Is4() {
		ip4 := s.Address.As4()
		ip = ip4[:]
	} else if s.Address.Is6() {
		ip6 := s.Address.As16()
		ip = ip6[:]
	} else {
		return nil
	}

	p := uint8(s.Protocol)

	return &ipset.Entry{IP: ip, Port: &(s.Port), Protocol: &p, Replace: true}
}

func (b *Balancer) INFO(s string, a ...any) { b.Logger.INFO(s, a...) }
func (b *Balancer) ERR(s string, a ...any)  { b.Logger.ERR(s, a...) }

func (b *Balancer) Configure(services []cue.Service) error {

	if len(b.vip) < 1 && b.IPSet != "" {

		ipset.Create(b.IPSet, "hash:ip,port", ipset.CreateOptions{Timeout: 300, Replace: true})
		//ipset.Create(b.IPSet, "hash:ip,port", ipset.CreateOptions{Replace: true})

		ipset.Flush(b.IPSet)
	}

	vip := map[netip.Addr]bool{}

	target := map[tuple]cue.Service{}

	for _, s := range services {
		target[tuple{addr: s.Address, port: s.Port, prot: s.Protocol}] = s
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {

		vip[s.Service.Address] = true

		key := tuple{addr: s.Service.Address, port: s.Service.Port, prot: uint8(s.Service.Protocol)}

		if t, wanted := target[key]; !wanted {

			if err := b.Client.RemoveService(s.Service); err != nil {
				b.ERR(logServRemove(s.Service).err(err))
			} else {
				b.INFO(logServRemove(s.Service).log())
			}

			if e := ipsetEntry(s.Service); e != nil && b.IPSet != "" {
				ipset.Del(b.IPSet, e)
			}

		} else {

			service := ipvsService(t)

			if service != s.Service {

				if err := b.Client.UpdateService(service); err != nil {
					b.ERR(logServUpdate(service, s.Service).err(err))
				} else {
					b.INFO(logServUpdate(service, s.Service).log())
				}
			}

			if e := ipsetEntry(service); e != nil && b.IPSet != "" {
				ipset.Add(b.IPSet, e)
			}

			b.destinations(s.Service, t.Destinations)

			delete(target, key)
		}
	}

	for _, t := range target {

		service := ipvsService(t)

		if err := b.Client.CreateService(service); err != nil {
			b.ERR(logServCreate(service).err(err))
			continue
		} else {
			b.INFO(logServCreate(service).log())
		}

		if e := ipsetEntry(service); e != nil && b.IPSet != "" {
			ipset.Add(b.IPSet, e)
		}

		b.destinations(service, t.Destinations)
	}

	// add service IP addresses to interface
	for v, _ := range vip {
		addr := netlinkAddr(v)
		if b.Link != nil && addr != nil {
			netlink.AddrAdd(*b.Link, netlinkAddr(v))
		}

		delete(b.vip, v) // ensure address doesn't get removed in next step
	}

	// remove any addresses which are no longer active
	for v, _ := range b.vip {
		addr := netlinkAddr(v)
		if b.Link != nil && addr != nil {
			netlink.AddrDel(*b.Link, netlinkAddr(v))
		}
	}

	b.vip = vip

	return nil
}

func (b *Balancer) destinations(s ipvs.Service, destinations []cue.Destination) error {

	target := map[ipport]cue.Destination{}

	for _, d := range destinations {
		target[ipport{Addr: d.Address, Port: d.Port}] = d
	}

	dsts, err := b.Client.Destinations(s)

	// above errors with "file does not exist" when no destinations present - which seems unhelpful
	//if err != nil {
	//	b.ERR(logServQuery(s).err(err))
	//}

	for _, d := range dsts {

		key := ipport{Addr: d.Address, Port: d.Port}

		if t, wanted := target[key]; !wanted {

			if err = b.Client.RemoveDestination(s, d.Destination); err != nil {
				b.ERR(logDestRemove(s, d.Destination).err(err))
			} else {
				b.INFO(logDestRemove(s, d.Destination).log())
			}

		} else {

			destination := ipvsDestination(t)

			if destination != d.Destination {

				if err := b.Client.UpdateDestination(s, destination); err != nil {
					b.ERR(logDestUpdate(s, destination, d.Destination).err(err))
				} else {
					b.INFO(logDestUpdate(s, destination, d.Destination).log())
				}
			}

			delete(target, key)
		}
	}

	for _, d := range target {

		destination := ipvsDestination(d)
		//destination.Address = netip.MustParseAddr("10.99.99.99") // force errors to test

		if err := b.Client.CreateDestination(s, destination); err != nil {
			b.ERR(logDestCreate(s, destination).err(err))
		} else {
			b.INFO(logDestCreate(s, destination).log())
		}
	}

	return nil
}

func ipvsService(s cue.Service) ipvs.Service {

	scheduler := "wrr"
	flags := ipvs.ServiceHashed //ipvs.ServicePersistent | ipvs.ServiceHashed
	netmask := netmask.MaskFrom4([4]byte{255, 255, 255, 255})

	return ipvs.Service{
		Address:   s.Address,
		Port:      s.Port,
		Protocol:  ipvs.Protocol(s.Protocol),
		Netmask:   netmask,
		Scheduler: scheduler,
		Flags:     flags,
		Family:    ipvs.INET,
		//Timeout:   uint32,
		//FWMark:    uint32,
	}
}

func ipvsDestination(d cue.Destination) ipvs.Destination {
	return ipvs.Destination{
		Address:   d.Address,
		Port:      d.Port,
		Family:    ipvs.INET,
		FwdMethod: ipvs.Masquerade,
		Weight:    uint32(d.HealthyWeight()),
		//UpperThreshold: uint32,
		//LowerThreshold: uint32,
		//TunnelType:  TunnelType,
		//TunnelPort:  uint16,
		//TunnelFlags: TunnelFlags,
	}
}

/**********************************************************************/
// Logging
/**********************************************************************/

type dest = ipvs.Destination
type serv = ipvs.Service

func logServEvent(e string, s serv, p ...ipvs.Service) *LE {
	kv := KV{"service": svc(s)}
	if len(p) > 0 {
		//kv.add("previous", svc(p[0]))
		kv["previous"] = svc(p[0])
	}
	return &LE{f: "service." + e, k: kv}
}

func logServQuery(s serv) *LE     { return logServEvent("query", s) }
func logServCreate(s serv) *LE    { return logServEvent("create", s) }
func logServRemove(s serv) *LE    { return logServEvent("remove", s) }
func logServUpdate(s, p serv) *LE { return logServEvent("update", s, p) }

func logDestEvent(e string, s ipvs.Service, d ipvs.Destination, p ...ipvs.Destination) *LE {
	kv := KV{"service": svc(s), "destination": dst(d)}
	if len(p) > 1 {
		//kv.add("previous", dst(p[0]))
		kv["previous"] = dst(p[0])
	}
	return &LE{f: "destination." + e, k: kv}
}

func logDestCreate(s serv, d dest) *LE    { return logDestEvent("create", s, d) }
func logDestRemove(s serv, d dest) *LE    { return logDestEvent("remove", s, d) }
func logDestUpdate(s serv, d, p dest) *LE { return logDestEvent("update", s, d, p) }

func svc(s ipvs.Service) string {
	js, _ := json.Marshal(s)
	return string(js)
	return fmt.Sprint(s)
}

func dst(d ipvs.Destination) string {
	js, _ := json.Marshal(d)
	return string(js)
	return fmt.Sprint(d)
}

type LE struct {
	k KV
	f string
}

func (l *LE) log() (string, KV)        { return l.f, l.k }
func (l *LE) err(e error) (string, KV) { l.k["error"] = e.Error(); return l.log() }
func (l *LE) add(k string, e any) *LE  { l.k[k] = e; return l }
