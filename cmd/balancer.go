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
	"net/netip"

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
	Logger Logger
}

type Client = ipvs.Client

func NewClient() (ipvs.Client, error) {
	return ipvs.New()
}

func (b *Balancer) DEBUG(s string, a ...any) { b.Logger.NOTICE(s, a...) }
func (b *Balancer) ERR(s string, a ...any)   { b.Logger.ERR(s, a...) }

func (b *Balancer) Configure(services []cue.Service) error {
	F := "service"

	target := map[tuple]cue.Service{}

	for _, s := range services {
		target[tuple{addr: s.Address, port: s.Port, prot: s.Protocol}] = s
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {

		key := tuple{addr: s.Service.Address, port: s.Service.Port, prot: uint8(s.Service.Protocol)}

		if t, wanted := target[key]; !wanted {

			b.DEBUG(F, "REMOVING", s.Service)

			if err := b.Client.RemoveService(s.Service); err != nil {
				b.ERR(F, "ERROR", s.Service, err)
			}

		} else {

			service := ipvsService(t)

			if service != s.Service {

				b.DEBUG(F, "UPDATING", s.Service, service)

				if err := b.Client.UpdateService(service); err != nil {
					b.ERR(F, "ERROR", s.Service, err)
				}
			}

			if err := b.destinations(s.Service, t.Destinations); err != nil {
				b.ERR(F, "ERROR", s.Service, err)
			}

			delete(target, key)
		}
	}

	for _, t := range target {
		service := ipvsService(t)

		b.DEBUG(F, "CREATING", service)

		if err := b.Client.CreateService(service); err != nil {
			b.ERR(F, "ERROR", service, err)
			continue
		}

		if err := b.destinations(service, t.Destinations); err != nil {
			b.ERR(F, "ERROR", service, err)
		}
	}

	return nil
}

func (b *Balancer) destinations(service ipvs.Service, destinations []cue.Destination) error {

	F := "destination"

	target := map[ipport]cue.Destination{}

	for _, d := range destinations {
		target[ipport{Addr: d.Address, Port: d.Port}] = d
	}

	dsts, err := b.Client.Destinations(service)

	if err != nil {
		b.ERR(F, "ERROR", service, err)
	}

	for _, d := range dsts {

		key := ipport{Addr: d.Address, Port: d.Port}

		if t, wanted := target[key]; !wanted {

			b.DEBUG(F, "REMOVING", d)

			if err = b.Client.RemoveDestination(service, d.Destination); err != nil {
				b.ERR(F, "ERROR", service, d.Destination)
			}

		} else {

			destination := ipvsDestination(t)

			if destination != d.Destination {

				b.DEBUG(F, "UPDATING", svc(service), dst(d.Destination), "to", dst(destination))

				if err := b.Client.UpdateDestination(service, destination); err != nil {
					b.ERR(F, "ERROR", service, destination)
				}
			}

			delete(target, key)
		}
	}

	for _, d := range target {

		b.DEBUG(F, "CREATING", d)

		destination := ipvsDestination(d)

		if err := b.Client.CreateDestination(service, destination); err != nil {
			b.ERR("ERROR", service, destination)
		}
	}

	return nil
}

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
