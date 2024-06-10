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
	"fmt"
	"net"
	"net/netip"
	"sync"

	"bufio"
	"os"
	"regexp"
	"strconv"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/mon"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
	"github.com/lrh3321/ipset-go"
	"github.com/vishvananda/netlink"
)

type Balancer struct {
	Client ipvs.Client
	Logger Logger
	Link   *netlink.Link
	IPSet  string

	mutex sync.Mutex
	state map[tuple]cue.Service
}

func (b *Balancer) Dest(s ipvs.Service, d ipvs.Destination) mon.Destination {
	// differs from DSR - dest port might be be different to service port
	return mon.Destination{Address: d.Address, Port: d.Port}
}

func (b *Balancer) summary() (r Summary) {

	services, _ := b.Client.Services()

	for _, s := range services {
		r.IngressOctets += s.Stats.IncomingBytes
		r.IngressPackets += s.Stats.IncomingPackets
		r.EgressOctets += s.Stats.OutgoingBytes
		r.EgressPackets += s.Stats.OutgoingPackets
		r.Flows += s.Stats.Connections
	}

	return
}

type Client = ipvs.Client

func NewClient() (ipvs.Client, error) {
	return ipvs.New()
}

func netlinkAddr(a netip.Addr) *netlink.Addr {

	if p, err := a.Prefix(a.BitLen()); err == nil {
		if i, err := netlink.ParseAddr(p.String()); err == nil {
			return i
		}
	}

	return nil
}

func (b *Balancer) INFO(s string, a ...any) { b.Logger.INFO(s, a...) }
func (b *Balancer) ERR(s string, a ...any)  { b.Logger.ERR(s, a...) }

// arrange to call every 60 seconds to maintain ipset & vips
func (b *Balancer) Maintain() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b._maintain()
}

// must be called under lock
func (b *Balancer) _vips() map[netip.Addr]bool {
	vips := map[netip.Addr]bool{}

	for t, _ := range b.state {
		vips[t.Address] = true
	}

	return vips
}

// must be called under lock
func (b *Balancer) _maintain() {

	ipset.Create(b.IPSet, "hash:ip,port", ipset.CreateOptions{Timeout: 90, Replace: true})

	for t, _ := range b.state {
		if e := ipsetEntry(t); e != nil && b.IPSet != "" {
			ipset.Add(b.IPSet, e)
		}
	}

	for v, _ := range b._vips() {
		if addr := netlinkAddr(v); b.Link != nil && addr != nil {
			netlink.AddrAdd(*b.Link, netlinkAddr(v))
		}
	}
}

func ipsetEntry(t tuple) *ipset.Entry {

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

	return &ipset.Entry{IP: ip, Port: &(t.Port), Protocol: &(t.Protocol), Replace: true}
}

func mapServices(services []cue.Service) map[tuple]cue.Service {
	target := map[tuple]cue.Service{}
	for _, s := range services {
		target[tuple{Address: s.Address, Port: s.Port, Protocol: s.Protocol}] = s
	}
	return target
}

func (b *Balancer) configure(services []cue.Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	vipsToRemove := b._vips()       // delete old vips if not still required
	todo := mapServices(services)   // services which will need to be configured
	b.state = mapServices(services) // update state for next time

	for t, _ := range todo {
		delete(vipsToRemove, t.Address) // don't remove required vips
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {

		if !s.Service.Address.Is4() && !s.Service.Address.Is6() {
			continue
		}

		key := tuple{Address: s.Service.Address, Port: s.Service.Port, Protocol: uint8(s.Service.Protocol)}

		if t, wanted := todo[key]; !wanted {

			if err := b.Client.RemoveService(s.Service); err != nil {
				b.ERR(logServRemove(s.Service).err(err))
			} else {
				b.INFO(logServRemove(s.Service).log())
			}

			if e := ipsetEntry(key); e != nil && b.IPSet != "" {
				ipset.Del(b.IPSet, e)
			}

		} else {
			service := ipvsService(t)
			drain := !t.Reset

			if service != s.Service {
				if err := b.Client.UpdateService(service); err != nil {
					b.ERR(logServUpdate(service, s.Service).err(err))
				} else {
					b.INFO(logServUpdate(service, s.Service).log())
				}
			}

			b.destinations(s.Service, drain, t.Destinations)

			delete(todo, key) // no need to create as it exists - take off the todo list
		}
	}

	// create any non-existing services
	for _, s := range todo {
		service := ipvsService(s)
		drain := !s.Reset

		if err := b.Client.CreateService(service); err != nil {
			b.ERR(logServCreate(service).err(err))
			continue
		} else {
			b.INFO(logServCreate(service).log())
		}

		b.destinations(service, drain, s.Destinations)
	}

	// remove any addresses which are no longer active
	for v, _ := range vipsToRemove {
		if addr := netlinkAddr(v); b.Link != nil && addr != nil {
			netlink.AddrDel(*b.Link, netlinkAddr(v))
		}
	}

	b._maintain() // make sure IP is on link device and ipset is populated

	return nil
}

func (b *Balancer) destinations(s ipvs.Service, drain bool, destinations []cue.Destination) error {

	target := map[ipport]cue.Destination{}

	for _, d := range destinations {
		if drain || d.HealthyWeight() > 0 {
			target[ipport{Address: d.Address, Port: d.Port}] = d
		}
	}

	dsts, err := b.Client.Destinations(s)

	// above errors with "file does not exist" when no destinations present - which seems unhelpful
	//if err != nil {
	//	b.ERR(logServQuery(s).err(err))
	//}

	for _, d := range dsts {

		key := ipport{Address: d.Address, Port: d.Port}

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

	scheduler, flags, _ := ipvsScheduler(s.Scheduler, s.Sticky)
	netmask := netmask.MaskFrom4([4]byte{255, 255, 255, 255})

	family := ipvs.INET

	if s.Address.Is6() {
		family = ipvs.INET6
	}

	return ipvs.Service{
		Address:   s.Address,
		Port:      s.Port,
		Protocol:  ipvs.Protocol(s.Protocol),
		Netmask:   netmask,
		Scheduler: scheduler,
		Flags:     flags,
		Family:    family,
		Timeout:   s.Persist,
		//FWMark:    uint32,
	}
}

func ipvsDestination(d cue.Destination) ipvs.Destination {

	family := ipvs.INET

	if d.Address.Is6() {
		family = ipvs.INET6
	}

	return ipvs.Destination{
		Address:   d.Address,
		Port:      d.Port,
		Family:    family,
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

func (b *Balancer) MAC(d ipvs.DestinationExtended) string {
	return ""
}

func (b *Balancer) TCPStats() map[mon.Instance]tcpstats {

	type l4 struct {
		ip   netip.Addr
		port uint16
	}

	type key struct {
		unto l4
		dest l4
	}

	re := regexp.MustCompile(`^(TCP)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+(\S+)\s+(\d+)$`)

	foo := map[mon.Instance]tcpstats{}

	file, err := os.OpenFile("/proc/net/ip_vs_conn", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return foo
	}
	defer file.Close()

	s := bufio.NewScanner(file)

	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) != 10 {
			continue
		}

		nilIP, _ := ip4("00000000")

		//fromIP, _ := ip4(m[2])
		untoIP, _ := ip4(m[4])
		destIP, _ := ip4(m[6])

		//fromPort, _ := port(m[3])
		untoPort, _ := port(m[5])
		destPort, _ := port(m[7])

		if untoIP == nilIP || destIP == nilIP || untoPort == 0 || destPort == 0 {
			continue
		}

		instance := mon.Instance{
			Service: mon.Service{
				Address:  untoIP,
				Port:     untoPort,
				Protocol: TCP,
			},
			Destination: mon.Destination{
				Address: destIP,
				Port:    destPort,
			},
		}

		state := m[8]
		//count, _ := strconv.ParseInt(m[9], 10, 64)

		v := foo[instance]

		switch state {
		case "SYN_RECV":
			v.SYN_RECV++
		case "ESTABLISHED":
			v.ESTABLISHED++
		case "CLOSE":
			v.CLOSE++
		case "TIME_WAIT":
			v.TIME_WAIT++
		}

		foo[instance] = v

	}

	//for k, v := range foo {
	//	fmt.Printf("%s:%d -> %s:%d %v\n", k.Service.Address, k.Service.Port, k.Destination.Address, k.Destination.Port, v)
	//}

	return foo
}

func ip4(s string) (r netip.Addr, b bool) {
	nl, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return r, false
	}

	var i [4]byte
	i[0] = byte(nl >> 24 % 256)
	i[1] = byte(nl >> 16 % 256)
	i[2] = byte(nl >> 8 % 256)
	i[3] = byte(nl % 256)

	return netip.AddrFrom4(i), true
}

func port(s string) (r uint16, b bool) {
	ns, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return r, false
	}

	if ns > 65535 || ns < 0 {
		return r, false
	}

	return uint16(ns), true
}

func ipvsScheduler(scheduler string, sticky bool) (string, ipvs.Flags, error) {
	// rr    - Round Robin
	// wrr   - Weighted Round Robin
	// lc    - Least-Connection
	// wlc   - Weighted  Least-Connection
	// lblc  - Locality-Based Least-Connection
	// lblcr - Locality-Based Least-Connection with Replication
	// dh    - Destination Hashing
	// sh    - Source Hashing: sh-fallback, sh-port
	// sed   - Shortest Expected Delay
	// nq    - Never Queue
	// fo    - Weighted Failover
	// ovf   - Weighted Overflow
	// mh    - Maglev Hashing: mh-fallback, mh-port

	const (
		MH_FALLBACK = ipvs.ServiceSchedulerOpt1
		MH_PORT     = ipvs.ServiceSchedulerOpt2
	)

	// ipvs.ServiceHashed seems to get set by default - set this or we
	// will have to update the service every time
	var flags ipvs.Flags = ipvs.ServiceHashed

	if sticky {
		flags |= ipvs.ServicePersistent
	}

	switch scheduler {
	case "":
		return "wlc", flags, nil
	case "roundrobin":
		return "wrr", flags, nil
	case "leastconn":
		return "wlc", flags, nil
	case "maglev":
		if sticky {
			return "mh", flags | MH_FALLBACK, nil
		}
		return "mh", flags | MH_FALLBACK | MH_PORT, nil
	}

	return "wlc", flags, fmt.Errorf("%s is not a valid scheduler name", scheduler)
}

func (b *Balancer) Stats(s ipvs.Stats) (r Stats) {

	r.IngressOctets = s.IncomingBytes
	r.IngressPackets = s.IncomingPackets
	r.EgressOctets = s.OutgoingBytes
	r.EgressPackets = s.OutgoingPackets
	r.Flows = s.Connections

	return r
}

func (b *Balancer) Service(s cue.Service) (ipvs.ServiceExtended, error) {
	xs := ipvs.Service{Address: s.Address, Port: s.Port, Protocol: ipvs.Protocol(s.Protocol), Family: ipvs.INET}
	return b.Client.Service(xs)
}

func (b *Balancer) Destinations(s cue.Service) ([]ipvs.DestinationExtended, error) {
	xs := ipvs.Service{Address: s.Address, Port: s.Port, Protocol: ipvs.Protocol(s.Protocol), Family: ipvs.INET}
	return b.Client.Destinations(xs)
}

func (b *Balancer) Destination(dst cue.Destination) mon.Destination {
	return mon.Destination{Address: dst.Address, Port: dst.Port}
}

func (b *Balancer) ServiceInstance(s cue.Service) mon.Instance {
	return mon.Instance{Service: mon.Service{Address: s.Address, Port: s.Port, Protocol: s.Protocol}}
}

func (b *Balancer) DestinationInstance(s cue.Service, d cue.Destination) mon.Instance {
	return mon.Instance{
		Service:     mon.Service{Address: s.Address, Port: s.Port, Protocol: s.Protocol},
		Destination: mon.Destination{Address: d.Address, Port: d.Port},
	}
}

// interface method called by mon when a destination's heatlh status transitions up or down
func (b *Balancer) Notify(instance mon.Instance, state bool) {
	if logger := b.Logger; logger != nil {
		logger.NOTICE("notify", notifyLog(instance, state))
	}
}

// interface method called by mon every time a round of checks for a destination is completed
func (b *Balancer) Result(instance mon.Instance, state bool, diagnostic string) {
	// return // we log all probes anyway - no need for this
	if logger := b.Logger; logger != nil {
		logger.DEBUG("result", resultLog(instance, state, diagnostic))
	}
}

func (b *Balancer) Check(instance mon.Instance, check string, round uint64, state bool, diagnostic string) {
	// return // we log all probes anyway - no need for this
	if logger := b.Logger; logger != nil {
		logger.DEBUG("check", checkLog(instance, state, diagnostic, check, round))
	}
}

func notifyLog(instance mon.Instance, status bool) map[string]any {

	proto := func(p uint8) string {
		switch instance.Service.Protocol {
		case TCP:
			return "tcp"
		case UDP:
			return "udp"
		}
		return fmt.Sprintf("%d", p)
	}

	return map[string]any{
		"state": updown(status),
		"proto": proto(instance.Service.Protocol),
		"saddr": instance.Service.Address.String(),
		"sport": instance.Service.Port,
		"daddr": instance.Destination.Address.String(),
		"dport": instance.Destination.Port,
	}
}

func resultLog(instance mon.Instance, status bool, diagnostic string) map[string]any {
	r := notifyLog(instance, status)
	r["diagnostic"] = diagnostic
	return r
}

func checkLog(instance mon.Instance, status bool, diagnostic string, check string, round uint64) map[string]any {
	r := resultLog(instance, status, diagnostic)
	r["check"] = check
	r["round"] = round
	return r
}
