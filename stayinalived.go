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
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/bgp4"

	"github.com/cloudflare/ipvs"
	"github.com/cloudflare/ipvs/netmask"
)

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target

var logger *Logger

var root = flag.String("r", "", "webserver root directory")
var websrv = flag.String("w", ":9999", "webserver address:port to listen on")
var nolabel = flag.Bool("N", false, "don't add 'name' label to prometheus metrics")
var level = flag.Uint("l", LOG_ERR, "debug level level")

type balancer struct {
	ipvs ipvs.Client
}

type serv struct {
	ip string
	l4 L4
}

type ipport struct {
	ip   IP4
	port uint16
}

func (f *balancer) Configure(h vc5.Healthchecks) {
	println("CONFIGURE")

	//j, err := json.MarshalIndent(&h, "", "  ")
	//fmt.Println(string(j))

	existing := map[serv]ipvs.Service{}

	services, err := f.ipvs.Services()

	for _, svc := range services {
		switch svc.Protocol {
		case ipvs.TCP:
			existing[serv{ip: svc.Address.String(), l4: L4{Protocol: false, Port: svc.Port}}] = svc.Service
		case ipvs.UDP:
			existing[serv{ip: svc.Address.String(), l4: L4{Protocol: true, Port: svc.Port}}] = svc.Service
		}
	}

	for vip, virtual := range h.Virtual {
		for l4, service := range virtual.Services {

			if false {
				fmt.Println(vip, l4, service.Healthy)
			}

			reals := map[ipport]bool{}

			for k, v := range service.Reals {
				//reals[ipport{ip: k, port: 8000}] = v.Probe.Passed
				reals[ipport{ip: k, port: l4.Port}] = v.Probe.Passed
			}

			proto := ipvs.TCP

			if l4.Protocol {
				proto = ipvs.UDP
			}

			svc := ipvs.Service{
				Address:   netip.AddrFrom4(vip),
				Netmask:   netmask.MaskFrom4([4]byte{255, 255, 255, 255}),
				Scheduler: "wrr",
				Port:      l4.Port,
				Family:    ipvs.INET,
				Protocol:  proto,
				Flags:     ipvs.ServiceHashed,
			}

			bar := serv{ip: svc.Address.String(), l4: L4{Protocol: false, Port: svc.Port}}

			if s, ok := existing[bar]; ok {

				if s != svc {

					log.Println("Service needs upafing in IPVS:", vip, l4, s, svc)

					err = f.ipvs.UpdateService(svc)

					if err != nil {
						log.Println("failed updating Service in IPVS", err)
					}
				}

			} else {

				log.Println("Creating Service in IPVS:", vip, l4)

				err = f.ipvs.CreateService(svc)

				if err != nil {
					log.Println("failed creating Service in IPVS", err)
				}
			}

			f.destinations(svc, reals)

			delete(existing, bar)
		}
	}

	for _, svc := range existing {
		if err = f.ipvs.RemoveService(svc); err != nil {
			log.Println("failed removing Service in IPVS", err)
		}
	}

}

func (f *balancer) destinations(svc ipvs.Service, reals map[ipport]bool) {

	vs := map[string]ipvs.DestinationExtended{}

	dests, err := f.ipvs.Destinations(svc)

	for _, dst := range dests {
		addr := fmt.Sprintf("%s:%d", dst.Address, dst.Port)
		vs[addr] = dst
	}

	for k, v := range reals {
		addr := fmt.Sprintf("%s:%d", k.ip, k.port)

		var weight uint32

		if v {
			weight = 1
		}

		dst := ipvs.Destination{
			Address:   netip.AddrFrom4(k.ip),
			FwdMethod: ipvs.Masquarade,
			Weight:    weight,
			Port:      k.port,
			Family:    ipvs.INET,
		}

		if d, ok := vs[addr]; ok {

			if d.Destination != dst {
				if err = f.ipvs.UpdateDestination(svc, dst); err != nil {
					log.Println("destination update failed", addr)
				}
			}

		} else {
			if err = f.ipvs.CreateDestination(svc, dst); err != nil {
				log.Println("error creating destination:", addr, err)
			}
		}

		delete(vs, addr)
	}

	for _, dst := range vs {
		f.ipvs.RemoveDestination(svc, dst.Destination)
	}
}

func (f *balancer) Close() {
}

/********************************************************************************/
func (f *balancer) Stats(h vc5.Healthchecks) map[vc5.Target]vc5.Counter {

	vs := map[string]vc5.Counter{}
	ret := map[vc5.Target]vc5.Counter{}

	services, err := f.ipvs.Services()

	if err != nil {
		return ret
	}

	for _, svc := range services {
		switch svc.Protocol {
		case ipvs.TCP:
		case ipvs.UDP:
		default:
			continue
		}

		s := svc.Service

		dests, _ := f.ipvs.Destinations(s)

		for _, dst := range dests {

			d := dst.Destination

			addr := fmt.Sprintf("%s:%d:%s:%s", s.Address, s.Port, s.Protocol, d.Address)

			c := dst.Stats64

			vs[addr] = vc5.Counter{
				//Concurrent: c.Connections,
				Octets:  c.OutgoingBytes,
				Packets: c.OutgoingPackets,
				//Octets:  c.IncomingBytes,
				//Packets: c.IncomingPackets,
			}

			/*
			   type Counter struct {
			       Octets      uint64
			       Packets     uint64
			       Flows       uint64
			       Concurrent  uint64
			       Blocked     uint64
			       Latency     uint64 // global only
			       QueueFailed uint64 // global only
			       DEFCON      uint8  // global only
			   }
			*/
		}

	}

	for vip, virtual := range h.Virtual {
		for l4, service := range virtual.Services {
			for rip, _ := range service.Reals {

				proto := ipvs.TCP

				if l4.Protocol {
					proto = ipvs.UDP
				}

				addr := fmt.Sprintf("%s:%d:%s:%s", vip, l4.Port, proto, rip)

				if c, ok := vs[addr]; ok {
					t := Target{VIP: vip, RIP: rip, Port: l4.Port, Protocol: l4.Protocol.Number()}
					ret[t] = c
				}

			}
		}
	}

	return ret
}

/********************************************************************************/

func main() {

	flag.Parse()
	args := flag.Args()

	logger = &Logger{Level: uint8(*level)}

	file := args[0]
	addr := args[1]

	conf, err := vc5.LoadConf(file)

	if conf.Webserver != "" {
		*websrv = conf.Webserver
	}

	s, err := net.Listen("tcp", *websrv)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := vc5.Load(conf)

	balancer := &balancer{}

	balancer.ipvs, err = ipvs.New()

	if err != nil {
		log.Fatalf("ipvs: %v", err)
	}

	pool := bgp4.Pool{
		Address:     addr,
		ASN:         conf.RHI.AS_Number,
		HoldTime:    conf.RHI.Hold_Time,
		Communities: conf.RHI.Communities(),
		Peers:       conf.RHI.Peers,
		Listen:      conf.RHI.Listen,
	}

	if !pool.Open() {
		log.Fatal("BGP peer initialisation failed")
	}

	lb := &vc5.BYOB{
		Logger: logger,
	}

	err = lb.Start(balancer, hc)

	if err != nil {
		log.Fatal(err)
	}

	go func() {
		time.Sleep(time.Duration(conf.Learn) * time.Second)
		pool.Start()
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGQUIT)
	//signal.Notify(sig) // all the signals!

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGUSR2:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err := vc5.LoadConf(file)

				if err != nil {
					log.Println(err)
				} else {
					if h, err := hc.Reload(conf); err != nil {
						log.Println(err)
					} else {
						hc = h
						pool.Peer(conf.RHI.Peers)
						lb.Update(hc)
					}
				}
			}
		}
	}()

	var stats *Stats
	start := time.Now()

	go func() {
		var t time.Time

		for {
			s := getStats(lb)
			s.Sub(stats, time.Now().Sub(t))
			t = time.Now()
			stats = s
			if time.Now().Sub(start) > (time.Duration(conf.Learn) * time.Second) {
				pool.NLRI(s.RHI)
			}
			time.Sleep(3 * time.Second)
		}
	}()

	static := http.FS(STATIC)
	var fs http.FileSystem

	if *root != "" {
		fs = http.FileSystem(http.Dir(*root))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if fs != nil {
			file := r.URL.Path
			if file == "" || file == "/" {
				file = "/index.html"
			}

			if f, err := fs.Open("/" + file); err == nil {
				f.Close()
				http.FileServer(fs).ServeHTTP(w, r)
				return
			}
		}

		r.URL.Path = "static/" + r.URL.Path // there must be a way to avoid this, surely ...
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		for _, l := range logger.Dump() {
			w.Write([]byte(fmt.Sprintln(l)))
		}
	})

	http.HandleFunc("/conf.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, err := json.MarshalIndent(conf, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, err := json.MarshalIndent(hc, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cf := lb.Status()
		j, err := json.MarshalIndent(cf, "", "  ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, _ := json.MarshalIndent(stats, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if stats == nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write(prometheus(stats, start))
		}
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		history := logger.Dump()

		re := regexp.MustCompile("^/log/([0-9]+)$")
		match := re.FindStringSubmatch(r.RequestURI)

		if match != nil && len(match) == 2 {
			n, _ := strconv.ParseInt(match[1], 10, 64)
			history = logger.Since(int64(n))
		}

		if j, err := json.MarshalIndent(history, "", "  "); err != nil {
			log.Println(err)
			w.Write([]byte(`[]`))
		} else {
			w.Write(j)
		}
		w.Write([]byte("\n"))
	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}
