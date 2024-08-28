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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"bufio"
	"os"
	"regexp"
	"strconv"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
	"github.com/lrh3321/ipset-go"
	"github.com/vishvananda/netlink"

	"vc5"
)

type Balancer struct {
	Client ipvs.Client
	Link   string
	IPSet  string

	link     *netlink.Link
	mutex    sync.Mutex
	state    map[vc5.Service]vc5.Manifest
	maintain chan bool
}

type KV = map[string]any
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

func _vips(state map[vc5.Service]vc5.Manifest) map[netip.Addr]bool {
	vips := map[netip.Addr]bool{}

	for t, _ := range state {
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

		for v, _ := range _vips(b.state) {
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

	for v, _ := range _vips(b.state) {
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

func mapServices(services []vc5.Manifest) map[vc5.Service]vc5.Manifest {

	target := map[vc5.Service]vc5.Manifest{}

	for _, s := range services {
		target[s.Service()] = s
	}

	return target
}

func from_ipvs(s ipvs.Service) vc5.Service {
	return vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}
}

func (b *Balancer) Configure(services []vc5.Manifest) error {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	vipsToRemove := _vips(b.state)  // old vips todelete if not still required
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

			if err := b.destinations(s.Service, drain, t.Destinations); err != nil {
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

		if err := b.destinations(service, drain, s.Destinations); err != nil {
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

func (b *Balancer) destinations(s ipvs.Service, drain bool, destinations []vc5.Backend) error {

	svc := vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}

	target := map[vc5.Destination]vc5.Backend{}

	for _, d := range destinations {
		if drain || d.HealthyWeight() > 0 {
			key := vc5.Destination{Address: d.Address, Port: d.Port}
			target[key] = d
		}
	}

	dsts, _ := b.Client.Destinations(s)

	// above errors with "file does not exist" when no destinations present - which seems unhelpful
	//if err != nil {
	//	b.ERR(logServQuery(s).err(err))
	//}

	for _, d := range dsts {

		key := vc5.Destination{Address: d.Address, Port: d.Port}

		if t, wanted := target[key]; !wanted {

			// this destination exists in the kernel but is no longer wanted - remove it
			if err := b.Client.RemoveDestination(s, d.Destination); err != nil {
				return fmt.Errorf("RemoveDestination(%s, %s) failed: %s", svc, key, err.Error())
			}

		} else {

			// this destination exists in the kernel and is still wanted
			destination := ipvsDestination(t)

			if destination != d.Destination {
				// if the settings for the destination in the kernel is not quite right then update it
				if err := b.Client.UpdateDestination(s, destination); err != nil {
					return fmt.Errorf("UpdateDestination(%s, %s) failed: %s", svc, key, err.Error())
				}
			}

			delete(target, key) // we don't need to create this in the next stage, so forget about it
		}
	}

	// create any destinations which don't exist in the kernel
	for key, d := range target {
		if err := b.Client.CreateDestination(s, ipvsDestination(d)); err != nil {
			return fmt.Errorf("CreateDestination(%s, %s) failed: %s", svc, key, err.Error())
		}
	}

	return nil
}

func ipvsService(s vc5.Manifest) ipvs.Service {

	scheduler, flags, _ := ipvsScheduler(s.Scheduler, s.Sticky)
	mask := netmask.MaskFrom4([4]byte{255, 255, 255, 255})
	family := ipvs.INET

	if s.Address.Is6() {
		family = ipvs.INET6
		mask = netmask.MaskFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	}

	return ipvs.Service{
		Address:   s.Address,
		Port:      s.Port,
		Protocol:  ipvs.Protocol(s.Protocol),
		Netmask:   mask,
		Scheduler: scheduler,
		Flags:     flags,
		Family:    family,
		Timeout:   s.Persist,
		//FWMark:    uint32,
	}
}

func ipvsDestination(d vc5.Backend) ipvs.Destination {

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

type TCPStats struct {
	SYN_RECV    uint64
	ESTABLISHED uint64
	CLOSE       uint64
	TIME_WAIT   uint64
}

func (b *Balancer) TCPStats() map[vc5.Instance]TCPStats {

	type l4 struct {
		ip   netip.Addr
		port uint16
	}

	type key struct {
		unto l4
		dest l4
	}

	re := regexp.MustCompile(`^(TCP)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+(\S+)\s+(\d+)$`)

	stats := map[vc5.Instance]TCPStats{}

	file, err := os.OpenFile("/proc/net/ip_vs_conn", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return stats
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

		instance := vc5.Instance{
			Service: vc5.Service{
				Address:  untoIP,
				Port:     untoPort,
				Protocol: vc5.TCP,
			},
			Destination: vc5.Destination{
				Address: destIP,
				Port:    destPort,
			},
		}

		state := m[8]
		//count, _ := strconv.ParseInt(m[9], 10, 64)

		v := stats[instance]

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

		stats[instance] = v

	}
	return stats
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

func updown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func (b *Balancer) Stats() map[vc5.Instance]vc5.Stats {

	tcpstats := b.TCPStats()

	stats := map[vc5.Instance]vc5.Stats{}

	services, _ := b.Client.Services()
	for _, s := range services {

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

	return stats
}

func (b *Balancer) Summary() (r vc5.Summary) {

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

func validate(config *vc5.Config) error {

	str := func(s vc5.Service) string {
		return fmt.Sprintf("%s:%d:%s", s.Address, s.Port, s.Protocol)
	}

	for t, s := range config.Services {
		if _, _, err := ipvsScheduler(s.Scheduler, s.Sticky); err != nil {
			return fmt.Errorf("Service %s : %s", str(t), err.Error())
		}
	}

	return nil
}

func httpEndpoints(client Client) {

	// Remove this if migrating to a different load balancing engine
	http.HandleFunc("/lb.json", func(w http.ResponseWriter, r *http.Request) {
		var ret []interface{}
		type status struct {
			Service      ipvs.ServiceExtended
			Destinations []ipvs.DestinationExtended
		}
		info, _ := client.Info()
		svcs, _ := client.Services()
		for _, se := range svcs {
			dsts, _ := client.Destinations(se.Service)
			ret = append(ret, status{Service: se, Destinations: dsts})
		}

		js, err := json.MarshalIndent(struct {
			Info     any
			Services []any
		}{
			Info:     info,
			Services: ret,
		}, "", " ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		js = append(js, 0x0a)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	})

}
