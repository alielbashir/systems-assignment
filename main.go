package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi"
)

func getIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello")
}

func main() {
	// Create router
	r := chi.NewRouter()

	r.Get("/", getIndex)

	log.Fatal(http.ListenAndServe(":8001", r))

	// GET /auth/:username

	// GET /verify

	// GET /README.txt

	// GET /stats
}
