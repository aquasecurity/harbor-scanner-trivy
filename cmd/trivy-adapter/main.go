package main

import (
	v1 "github.com/aquasecurity/harbor-trivy-adapter/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/image/trivy"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
)

type config struct {
	addr string
}

func main() {
	cfg := getConfig()
	log.Printf("Starting harbor-trivy-adapter with config %v", cfg)

	scanner, err := trivy.NewScanner()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{detailsKey}").HandlerFunc(apiHandler.GetScanResult)

	err = http.ListenAndServe(cfg.addr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func getConfig() config {
	cfg := config{
		addr: ":8080",
	}
	if addr, ok := os.LookupEnv("ADAPTER_ADDR"); ok {
		cfg.addr = addr
	}
	return cfg
}
