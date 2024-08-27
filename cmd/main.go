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
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vc5"
)

// TODO:
// * put logging back in
// * merge manager changes back to vc5 repo

func main() {
	main_()
	time.Sleep(5 * time.Second)
}

func main_() {

	F := "vc5"

	webroot := flag.String("r", "", "webserver root directory")
	webserver := flag.String("w", ":80", "webserver listen address")
	addr := flag.String("a", "", "address")
	ipset := flag.String("s", "", "ipset")
	iface := flag.String("i", "", "interface to add VIPs to")
	sni := flag.Bool("S", false, "Enable SNI mode for probes")
	asn := flag.Uint("A", 0, "Autonomous system number to enable loopback BGP") // experimental - may change

	flag.Parse()

	args := flag.Args()
	file := args[0]

	config, err := vc5.Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", err)
	}

	if err = validate(config); err != nil {
		log.Fatal("Couldn't validate config file: ", err)
	}

	logs := vc5.NewLogger(config.HostID, config.LoggingConfig())

	if config.Address != "" {
		*addr = config.Address
	}

	if config.Webserver != "" {
		*webserver = config.Webserver
	}

	if config.Webroot != "" {
		*webroot = config.Webroot
	}

	address := netip.MustParseAddr(*addr)

	if !address.Is4() {
		//logs.EMERG(F, "Address is not IPv4:", address)
		log.Fatal("Address is not IPv4: ", address)
	}

	routerID := address.As4()

	var listener net.Listener

	if *webserver != "" {
		listener, err = net.Listen("tcp", *webserver)
		if err != nil {
			log.Fatal(err)
		}
	}

	if config.Listen {
		l, err := net.Listen("tcp", ":179")
		if err != nil {
			log.Fatal("Couldn't listen on BGP port", err)
		}
		go bgpListener(l, logs.Sub("bgp"))
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
		Logger: logs.Sub("balancer"),
		Link:   *iface,
		IPSet:  *ipset,
	}

	// Run server to maintain ipsets and vips on dummy interface
	if err = balancer.start(ctx); err != nil {
		logs.Fatal(F, "balancer", KV{"error.message": err.Error()})
	}

	// The manager handles the main event loop, healthchecks, requests
	// for the console/metrics, sets up BGP sessions, etc.
	manager := vc5.Manager{
		Config:   config,
		Balancer: balancer,
		Logs:     logs,
		WebRoot:  *webroot,     // Serve static files from this directory
		RouterID: routerID,     // BGP router ID to use to speak to peers
		LocalBGP: uint16(*asn), // If non-zero then loopback BGP is activated
		Address:  address,      // Required for SYN probes
		SNI:      *sni,         // Needs to be true for servers tha are picky about SNI names
	}

	if err := manager.Manage(ctx, listener); err != nil {
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
				config.Address = *addr
				config.Webserver = *webserver
				config.Webroot = *webroot
				manager.Configure(config)
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

func bgpListener(l net.Listener, logs vc5.Logger) {
	F := "listener"

	for {
		conn, err := l.Accept()

		if err != nil {
			logs.Event(vc5.ERR, F, "accept", KV{"error.message": err.Error()})
		} else {
			go func(c net.Conn) {
				logs.Event(vc5.INFO, F, "accept", KV{"client.address": conn.RemoteAddr().String()})
				defer c.Close()
				time.Sleep(time.Second * 10)
			}(conn)
		}
	}
}
