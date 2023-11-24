package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/bgp"
)

/*

TDOD:

* expiry for ipset + periodic updates

*/

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target
type Balancer = vc5.Balancer

var logger *Logger

var set = flag.String("s", "", "ipset to add/delete IP/port to (type hash:ip,port)")
var iface = flag.String("i", "lo", "interface to add VIPs to")
var root = flag.String("r", "", "webserver root directory")
var websrv = flag.String("w", ":9999", "webserver address:port to listen on")
var nolabel = flag.Bool("N", false, "don't add 'name' label to prometheus metrics")
var level = flag.Uint("l", LOG_ERR, "debug level level")

func main() {

	flag.Parse()
	args := flag.Args()

	logger = &Logger{Level: uint8(*level)}

	file := args[0]
	addr := args[1]

	conf, err := vc5.LoadConf(file)

	if err != nil {
		log.Fatal(err)
	}

	if true {
		j, err := json.MarshalIndent(conf, "", "    ")
		fmt.Println(string(j), err)
		//return
	}

	if conf.Webserver != "" {
		*websrv = conf.Webserver
	}

	s, err := net.Listen("tcp", *websrv)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := vc5.Load(conf)

	if err != nil {
		log.Fatal(err)
	}

	balancer, err := New(*set, *iface)

	if err != nil {
		log.Fatalf("balancer: %v", err)
	}

	/*
			pool := bgp4.Pool{
				Address:     addr,
				ASN:         conf.RHI.AS_Number,
				HoldTime:    conf.RHI.Hold_Time,
				Communities: conf.RHI.Communities(),
				Peers:       conf.RHI.Peers,
				Listen:      conf.RHI.Listen,
				MED:         conf.RHI.MED,
				LocalPref:   conf.RHI.Local_Pref,
			}


		if !pool.Open() {
			log.Fatal("BGP peer initialisation failed")
		}
	*/

	pool := bgp4.NewPool(addr, conf.BGP, nil)

	fmt.Println(conf.BGP)

	director := &vc5.Director{
		Balancer: balancer,
		Logger:   logger,
	}

	err = director.Start(addr, hc)

	if err != nil {
		log.Fatal(err)
	}

	/*
		go func() {
			time.Sleep(time.Duration(conf.Learn) * time.Second)
			pool.Start()
		}()
	*/

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGUSR2)
	//signal.Notify(sig) // all the signals!

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGUSR2:
				fallthrough
			case syscall.SIGINT:
				log.Println("RELOAD")
				//time.Sleep(1 * time.Second)

				conf, err := vc5.LoadConf(file)

				if err != nil {
					log.Println(err)
				} else {
					if h, err := hc.Reload(conf); err != nil {
						log.Println(err)
					} else {
						hc = h
						//pool.Peer(conf.RHI.Peers)
						director.Update(hc)

						pool.Configure(conf.BGP)
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
			s := getStats(balancer)
			s.Sub(stats, time.Now().Sub(t))
			t = time.Now()
			stats = s
			if time.Now().Sub(start) > (time.Duration(conf.Learn) * time.Second) {
				//pool.NLRI(s.RHI)

				rhi := s.RHI

				var rib []bgp4.IP
				for k, v := range rhi {

					var ip bgp4.IP4

					if v && ip.UnmarshalText([]byte(k)) == nil {
						rib = append(rib, ip)
					}
				}

				pool.RIB(rib)
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
		cf := director.Status()
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
