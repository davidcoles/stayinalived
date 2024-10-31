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
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"

	"vc5"
)

type Client = ipvs.Client

func NewClient() (ipvs.Client, error) {
	return ipvs.New()
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

func ipvsDestination(d vc5.DestinationSpec) ipvs.Destination {

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

type tcpstats struct {
	SYN_RECV    uint64
	ESTABLISHED uint64
	CLOSE       uint64
	TIME_WAIT   uint64
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

		// perhaps migrate code to the below - avoiding persistent
		// flag for maglev. using fallback with no port is a good
		// approximation to sticky, without having to use 'reset'
		// (remove the destination, rather than set weight to 0 which
		// still allows new connections to a dead backend in ipvs)
		// because the fallback option checks for weight of 0. This
		// will allow connections to drain from a backend naturally.

		//flags = ipvs.ServiceHashed | MH_FALLBACK
		//if sticky {
		//	return "mh", flags, nil
		//}
		//return "mh", flags | MH_PORT, nil
	}

	return "wlc", flags, fmt.Errorf("%s is not a valid scheduler name", scheduler)
}

func updown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func tcpStats() map[vc5.Instance]tcpstats {

	type l4 struct {
		ip   netip.Addr
		port uint16
	}

	type key struct {
		unto l4
		dest l4
	}

	re := regexp.MustCompile(`^(TCP)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+(\S+)\s+(\d+)$`)

	stats := map[vc5.Instance]tcpstats{}

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

func ipvsSyncDestinations(c Client, s ipvs.Service, destinations []vc5.DestinationSpec, drain bool) error {

	svc := vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}

	target := map[vc5.Destination]vc5.DestinationSpec{}

	for _, d := range destinations {
		if drain || d.HealthyWeight() > 0 {
			key := vc5.Destination{Address: d.Address, Port: d.Port}
			target[key] = d
		}
	}

	dsts, _ := c.Destinations(s)

	// above errors with "file does not exist" when no destinations present - which seems unhelpful
	//if err != nil {
	//	b.ERR(logServQuery(s).err(err))
	//}

	for _, d := range dsts {

		key := vc5.Destination{Address: d.Address, Port: d.Port}

		if t, wanted := target[key]; !wanted {

			// this destination exists in the kernel but is no longer wanted - remove it
			if err := c.RemoveDestination(s, d.Destination); err != nil {
				return fmt.Errorf("RemoveDestination(%s, %s) failed: %s", svc, key, err.Error())
			}

		} else {

			// this destination exists in the kernel and is still wanted
			destination := ipvsDestination(t)

			if destination != d.Destination {
				// if the settings for the destination in the kernel is not quite right then update it
				if err := c.UpdateDestination(s, destination); err != nil {
					return fmt.Errorf("UpdateDestination(%s, %s) failed: %s", svc, key, err.Error())
				}
			}

			delete(target, key) // we don't need to create this in the next stage, so forget about it
		}
	}

	// create any destinations which don't exist in the kernel
	for key, d := range target {
		if err := c.CreateDestination(s, ipvsDestination(d)); err != nil {
			return fmt.Errorf("CreateDestination(%s, %s) failed: %s", svc, key, err.Error())
		}
	}

	return nil
}
