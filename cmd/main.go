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
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"

	lb "github.com/cloudflare/ipvs"
	"github.com/vishvananda/netlink"
)

// TODO:

//go:embed static/*
var STATIC embed.FS

func main() {

	F := "vc5"

	var mutex sync.Mutex

	start := time.Now()
	webroot := flag.String("r", "", "webserver root directory")
	webserver := flag.String("w", ":80", "webserver listen address")
	addr := flag.String("a", "", "address")
	ipset := flag.String("s", "", "ipset")
	iface := flag.String("i", "", "interface to add VIPs to")
	sni := flag.Bool("S", false, "Enable SNI mode for probes")

	flag.Parse()

	args := flag.Args()

	file := args[0]

	config, err := Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", err)
	}

	if err = validate(config); err != nil {
		log.Fatal("Couldn't validate config file: ", err)
	}

	logs := &sink{}
	logs.start(config.logging())

	var link *netlink.Link
	if *iface != "" {
		l, err := netlink.LinkByName(*iface)
		if err != nil {
			logs.EMERG(F, "Couldn't open netlink:", err)
			log.Fatal(err)
		}
		link = &l
	}

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
		logs.EMERG(F, "Address is not IPv4:", address)
		log.Fatal("Address is not IPv4: ", address)
	}

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
		go bgpListener(l, logs.sub("bgp"))
	}

	client, err := NewClient()

	if err != nil {
		logs.EMERG(F, "Couldn't start client (check IPVS modules are loaded):", err)
		log.Fatal("Couldn't start client (check IPVS modules are loaded):", err)
	}

	pool := bgp.NewPool(address.As4(), config.BGP, nil, logs.sub("bgp"))

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	balancer := &Balancer{
		Client: client,
		Logger: logs.sub("ipvs"),
		Link:   link,
		IPSet:  *ipset,
	}

	director := &cue.Director{
		Address:  address,
		Notifier: balancer,
		SNI:      *sni,
	}

	err = director.Start(config.parse())

	if err != nil {
		logs.EMERG(F, "Couldn't start director:", err)
		log.Fatal(err)
	}

	done := make(chan bool)

	vip := map[netip.Addr]State{}

	var rib []netip.Addr
	var summary Summary

	services, old, _ := serviceStatus(config, balancer, director, nil)

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-done:
				return
			}
			balancer.Maintain()
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			//summary.update(client, uint64(time.Now().Sub(start)/time.Second))
			summary.update(balancer.summary(), start)
			services, old, summary.Current = serviceStatus(config, balancer, director, old)
			mutex.Unlock()
			select {
			case <-ticker.C:
			case <-done:
				return
			}
		}
	}()

	go func() { // advertise VIPs via BGP
		timer := time.NewTimer(config.Learn * time.Second)
		ticker := time.NewTicker(5 * time.Second)
		services := director.Status()

		defer func() {
			ticker.Stop()
			timer.Stop()
			pool.RIB(nil)
			time.Sleep(2 * time.Second)
			pool.Close()
		}()

		var initialised bool
		for {
			select {
			case <-ticker.C: // check for matured VIPs
			case <-director.C: // a backend has changed state
				//services = director.Status()
				mutex.Lock()
				services = director.Status()
				balancer.configure(services)
				mutex.Unlock()
			case <-done: // shuting down
				return
			case <-timer.C:
				logs.NOTICE(F, KV{"event": "Learn timer expired"})
				initialised = true
			}

			mutex.Lock()
			vip = vipState(services, vip, config.priorities(), logs)
			rib = adjRIBOut(vip, initialised)
			mutex.Unlock()

			pool.RIB(rib)
		}
	}()

	log.Println("Initialised")

	static := http.FS(STATIC)
	var fs http.FileSystem

	if *webroot != "" {
		fs = http.FileSystem(http.Dir(*webroot))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if fs != nil {
			file := r.URL.Path
			if file == "/" {
				file = "/index.html"
			}

			if f, err := fs.Open(file); err == nil {
				f.Close()
				http.FileServer(fs).ServeHTTP(w, r)
				return
			}
		}

		r.URL.Path = "static/" + r.URL.Path
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {

		start, _ := strconv.ParseUint(r.URL.Path[5:], 10, 64)
		logs := logs.get(start)
		js, err := json.MarshalIndent(&logs, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/build.json", func(w http.ResponseWriter, r *http.Request) {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		js, err := json.MarshalIndent(info, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	// // Remove this if migrating to a different load balancing engine
	http.HandleFunc("/lb.json", func(w http.ResponseWriter, r *http.Request) {
		var ret []interface{}
		type status struct {
			Service      lb.ServiceExtended
			Destinations []lb.DestinationExtended
		}
		info, _ := client.Info()
		svcs, _ := client.Services()
		for _, se := range svcs {
			dsts, _ := client.Destinations(se.Service)
			ret = append(ret, status{Service: se, Destinations: dsts})
		}
		//js, err := json.MarshalIndent(&ret, " ", " ")
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
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {

		config.Address = *addr
		config.Webserver = *webserver
		config.Webroot = *webroot

		js, err := json.MarshalIndent(config, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/cue.json", func(w http.ResponseWriter, r *http.Request) {
		js, err := json.MarshalIndent(director.Status(), " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		js, err := json.MarshalIndent(struct {
			Summary  Summary               `json:"summary"`
			Services map[VIP][]Serv        `json:"services"`
			BGP      map[string]bgp.Status `json:"bgp"`
			VIP      []VIPStats            `json:"vip"`
			RIB      []netip.Addr          `json:"rib"`
			Logging  LogStats              `json:"logging"`
		}{
			Summary:  summary,
			Services: services,
			BGP:      pool.Status(),
			VIP:      vipStatus(services, vip),
			RIB:      rib,
			Logging:  logs.Stats(),
		}, " ", " ")
		mutex.Unlock()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {

		mutex.Lock()
		metrics := prometheus("stayinalived", services, summary, vip)
		mutex.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Join(metrics, "\n") + "\n"))
	})

	go func() {
		server := http.Server{}
		log.Fatal(server.Serve(listener))
	}()

	sig := make(chan os.Signal, 10)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGUSR2:
			logs.NOTICE(F, "Reload signal received")

			conf, err := Load(file)

			if err != nil {
				logs.ALERT(F, "Couldn't load config file: ", file, err)
				break
			}

			if err = validate(conf); err != nil {
				logs.ALERT(F, "Couldn't validate config file: ", file, err)
				break
			}

			mutex.Lock()
			config = conf
			director.Configure(config.parse())
			pool.Configure(config.BGP)
			mutex.Unlock()

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			logs.ALERT(F, "Shutting down")
			fmt.Println("CLOSING")
			close(done) // shut down BGP, etc
			time.Sleep(4 * time.Second)
			fmt.Println("DONE")
			return
		}
	}
}

func validate(config *Config) error {

	for t, s := range config.Services {
		if _, _, err := ipvsScheduler(s.Scheduler, s.Sticky); err != nil {
			return fmt.Errorf("Service %s : %s", t.string(), err.Error())
		}
	}

	return nil
}
