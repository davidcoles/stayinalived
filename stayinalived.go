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
	"github.com/davidcoles/vc5/bgp4"
)

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target

var logger *Logger

var ipset = flag.String("i", "", "ipset")
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

	if conf.Webserver != "" {
		*websrv = conf.Webserver
	}

	s, err := net.Listen("tcp", *websrv)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := vc5.Load(conf)

	//balancer := &balancer{
	//}
	balancer, err := New(*ipset)

	if err != nil {
		log.Fatalf("balancer: %v", err)
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
			time.Sleep(11 * time.Second)
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
