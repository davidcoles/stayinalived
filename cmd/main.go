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
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudflare/ipvs"

	"vc5"
)

// TODO:
// * merge manager changes back to vc5 repo

type KV = map[string]any

func main() {

	defer time.Sleep(5 * time.Second)

	F := "vc5"

	webroot := flag.String("r", "", "webserver root directory")
	webserver := flag.String("w", ":80", "webserver listen address")
	listen := flag.Bool("b", false, "Enable BGP listener on port 179")
	ipset := flag.String("s", "", "ipset")
	iface := flag.String("i", "", "interface to add VIPs to")
	//sni := flag.Bool("S", false, "Enable SNI mode for probes")
	asn := flag.Uint("A", 0, "Autonomous system number to enable loopback BGP") // experimental - may change
	hardfail := flag.Bool("H", false, "Hard fail on configuration apply")       // experimental - may change

	hostid := flag.String("h", "", "Host ID for logging")

	flag.Parse()

	args := flag.Args()
	addr := args[0]
	file := args[1]

	config, err := vc5.Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", err)
	}

	if err = validate(config); err != nil {
		log.Fatal("Couldn't validate config file: ", err)
	}

	if *hostid == "" {
		*hostid = addr
	}

	logs := vc5.NewLogger(*hostid, config.LoggingConfig())

	address, err := netip.ParseAddr(addr)

	if err != nil {
		logs.Fatal(F, "args", KV{"error.message": "Invalid address"})
	}

	if !address.Is4() {
		//logs.EMERG(F, "Address is not IPv4:", address)
		log.Fatal("Address is not IPv4: ", address)
	}

	routerID := address.As4()

	var webListener net.Listener

	if *webserver != "" {
		webListener, err = net.Listen("tcp", *webserver)
		if err != nil {
			log.Fatal(err)
		}
	}

	if *listen {
		err = bgpListener(logs)
		if err != nil {
			log.Fatal(err)
		}
	}

	client, err := NewClient()

	if err != nil {
		//logs.EMERG(F, "Couldn't start client (check IPVS modules are loaded):", err)
		log.Fatal("Couldn't start client (check IPVS modules are loaded):", err)
	}

	// Add some custom HTTP endpoints to the default mux to handle
	// requests specific to this type of load balancer client
	httpEndpoints(client)

	// context to use for shutting down services when we're about to exit
	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	// Create a balancer instance - this implements interface methods
	// (configuration changes, stats requests, etc). which are called
	// by the manager object (which handles the main event loop)
	balancer := &Balancer{
		Client: client,
		Link:   *iface,
		IPSet:  *ipset,
	}

	// Run server to maintain ipsets and vips on dummy interface
	if err = balancer.start(ctx); err != nil {
		logs.Fatal(F, "balancer", KV{"error.message": err.Error()})
	}

	*hardfail = true

	// The manager handles the main event loop, healthchecks, requests
	// for the console/metrics, sets up BGP sessions, etc.
	manager := &vc5.Manager{
		Balancer: balancer,
		Logs:     logs,
		Address:  address,  // Required for SYN probes
		RouterID: routerID, // BGP router ID to use to speak to peers
		//SNI:         *sni,         // Needs to be true for servers that are picky about SNI names (should really be the default)
		WebRoot:     *webroot,     // Serve static files from this directory
		BGPLoopback: uint16(*asn), // If non-zero then loopback BGP is activated
		//BGPListener: bgpListener,  // Listen for incoming BGP connections if not nil
		WebListener: webListener, // Listen for incoming web connections if not nil
		HardFail:    *hardfail,   // Exit if the balancer's Configure() argment returns an error (should really be the default)
	}

	if err := manager.Manage(ctx, config); err != nil {
		logs.Fatal(F, "manager", KV{"error.message": "Couldn't start manager: " + err.Error()})
	}

	// We are succesfully up and running, so send a high priority
	// alert to let the world know - perhaps we crashed previously and
	// were restarted by the service manager
	logs.Alert(vc5.ALERT, F, "initialised", KV{}, "Initialised")

	// We now wait for signals to tell us to reload the configuration file or exit
	sig := make(chan os.Signal, 10)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGUSR2:
			logs.Alert(vc5.NOTICE, F, "reload", KV{}, "Reload signal received")
			conf, err := vc5.Load(file)

			if err == nil {
				err = validate(conf)
			}

			if err == nil {
				config = conf
				manager.Configure(conf)
			} else {
				text := "Couldn't load config file " + file + " :" + err.Error()
				logs.Alert(vc5.ALERT, F, "config", KV{"file.path": file, "error.message": err.Error()}, text)
			}

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			logs.Alert(vc5.ALERT, F, "exiting", KV{}, "Exiting")
			return
		}
	}
}

func bgpListener(logs vc5.Logger) error {
	F := "bgp.listener"

	l, err := net.Listen("tcp", ":179")

	if err == nil {
		go func() {
			for {
				conn, err := l.Accept()

				if err != nil {
					logs.Event(vc5.ERR, F, "accept", KV{"error.message": err.Error()})
				} else {
					go func(c net.Conn) {
						defer c.Close()
						logs.Event(vc5.INFO, F, "accept", KV{"client.address": conn.RemoteAddr().String()})
						time.Sleep(time.Second * 10)
					}(conn)
				}
			}
		}()
	}

	return err
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
