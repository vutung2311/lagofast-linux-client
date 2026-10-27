package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lagofast/lagofast-vpn/pkg/nm"
)

const Version = "1.0.0"

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nm-lagofast-service version %s\n", Version)
		os.Exit(0)
	}

	log.SetPrefix("[nm-lagofast-service] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if *debug {
		log.Println("Debug logging enabled")
	}

	service, err := nm.NewPluginService()
	if err != nil {
		log.Fatalf("Fatal: failed to initialize NetworkManager plugin service: %v", err)
	}

	if err := service.Run(); err != nil {
		log.Fatalf("Service terminated with error: %v", err)
	}
}
