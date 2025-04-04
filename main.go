package main

import (
    "log"
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
	

)

func main() {
    db, err := setupDatabase("./users.db") // de
    if err != nil {
        log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
    }
    defer db.Close()

    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(configureCORS()) // d
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("API de Login v1.0"))
    })

    port := ":3000"
    log.Printf("Servidor escuchando en puerto %s", port)
    log.Fatal(http.ListenAndServe(port, r))
}
