package main

import (
  "encoding/json"
  "net/http"
  chi "github.com/go-chi/chi/v5"
)

func main() {
  r := chi.NewRouter()
  r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status":"ok"})
  })
  http.ListenAndServe(":8080", r)
}
