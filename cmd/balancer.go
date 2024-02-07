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
	//"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
	"github.com/davidcoles/cue"
)

type tuple struct {
	addr netip.Addr
	port uint16
	prot uint8
}

type Balancer struct {
	Client ipvs.Client
}

type Client = ipvs.Client

func NewClient() (ipvs.Client, error) {
	return ipvs.New()
}

func (b *Balancer) Configure(services []cue.Service) error {

	target := map[tuple]cue.Service{}

	for _, s := range services {
		target[tuple{addr: s.Address, port: s.Port, prot: s.Protocol}] = s
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {

		key := tuple{addr: s.Service.Address, port: s.Service.Port, prot: uint8(s.Service.Protocol)}

		if t, wanted := target[key]; !wanted {

			fmt.Println("REMOVING", s.Service)

			if err := b.Client.RemoveService(s.Service); err != nil {
				// do something
				fmt.Println("ERROR", s.Service, err)
			}
		} else {

			service := ipvsService(t)

			if service != s.Service {

				fmt.Println("UPDATING", s.Service, service)

				if err := b.Client.UpdateService(service); err != nil {
					// do something
					fmt.Println("ERROR", s.Service, err)
				}
			}

			if err := b.desinations(s.Service, t.Destinations); err != nil {
				// do something
				fmt.Println("ERROR", s.Service, err)
			}

			delete(target, key)
		}
	}

	for _, t := range target {
		service := ipvsService(t)

		fmt.Println("CREATING", service)

		if err := b.Client.CreateService(service); err != nil {
			fmt.Println("ERROR", service, err)
			continue
		}

		if err = b.foobar(service, t.Destinations); err != nil {
			// do something
		}
	}

	return nil
}

func (b *Balancer) destinations(service ipvs.Service, destinations []cue.Destination) error {

	target := map[ipport]cue.Destination{}

	for _, d := range destinations {
		target[ipport{Addr: d.Address, Port: d.Port}] = d
	}

	dsts, err := b.Client.Destinations(service)

	if err != nil {
		// do something
	}

	for _, d := range dsts {

		key := ipport{Addr: d.Address, Port: d.Port}

		if t, wanted := target[key]; !wanted {

			fmt.Println("REMOVING", d)

			if err = b.Client.RemoveDestination(service, d.Destination); err != nil {
				// do something
				fmt.Println("ERROR", service, d.Destination)
			}

		} else {
			// compare/update
			destination := ipvsDestination(t)

			if destination != d.Destination {

				fmt.Println("UPDATING", d)

				if err := b.Client.UpdateDestination(service, destination); err != nil {
					// do something
					fmt.Println("ERROR", service, destination)
				}
			}

			delete(target, key)
		}
	}

	for _, d := range target {

		fmt.Println("CREATING", d)

		destination := ipvsDestination(d)

		if err := b.Client.CreateDestination(service, destination); err != nil {
			fmt.Println("ERROR", service, destination)
			// do something
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

func (s *Summary) summary(c Client) {
	var u Stats

	services, _ := c.Services()

	for _, s := range services {
		u.Octets += s.Stats.IncomingBytes
		u.Packets += s.Stats.IncomingPackets
		u.Flows += s.Stats.Connections
	}

	s.Octets = u.Octets
	s.Packets = u.Packets
	s.Flows = u.Flows
}

func (s *Stats) update(u ipvs.Stats) Stats {
	o := *s

	//s.Octets = u.IncomingBytes
	//s.Packets = u.IncomingPackets

	s.Octets = u.OutgoingBytes
	s.Packets = u.OutgoingPackets
	s.Flows = u.Connections
	//s.Current = u.Current
	s.time = time.Now()

	if o.time.Unix() != 0 {
		diff := uint64(s.time.Sub(o.time) / time.Millisecond)

		if diff != 0 {
			s.PacketsPerSecond = (1000 * (s.Packets - o.Packets)) / diff
			s.OctetsPerSecond = (1000 * (s.Octets - o.Octets)) / diff
			s.FlowsPerSecond = (1000 * (s.Flows - o.Flows)) / diff
		}
	}

	return *s
}
