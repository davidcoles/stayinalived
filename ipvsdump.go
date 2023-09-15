package main

import (
	"fmt"
	"log"

	"github.com/cloudflare/ipvs"
)

func main() {
	vs, err := ipvs.New()

	if err != nil {
		log.Fatal(err)
	}

	services, err := vs.Services()

	if err != nil {
		log.Fatal(err)
	}

	for _, service := range services {
		fmt.Println(service)

		destinations, err := vs.Destinations(service.Service)

		if err == nil {
			for _, destination := range destinations {
				fmt.Println(" ", destination)
			}
		}
	}
}
