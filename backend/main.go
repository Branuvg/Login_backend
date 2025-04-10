package main

import (
    "log"
    "net/http"
    
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    
	"myapp/handlers"
    
    //cors
    "github.com/go-chi/cors"

    //database
    "database/sql"
    _ "modernc.org/sqlite" // Driver SQLite puro Go

)

func main() {
    // Conectar a la base de datos
    db, err := setupDatabase("../db/users.db")
    if err != nil {
        log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
    }
    defer db.Close() // Asegurar que se cierre al final

    // Crear router Chi
    r := chi.NewRouter()

    // Middlewares
    r.Use(middleware.Logger)    // Loggea cada request
    r.Use(middleware.Recoverer) // Recupera de panics
    r.Use(configureCORS())      // Aplica nuestra configuración CORS

    // Rutas Públicas (sin autenticación requerida inicialmente)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("API de Login v1.0"))
    })
    r.Post("/register", handlers.PostRegisterHandler(db))
    r.Post("/login", handlers.PostLoginHandler(db))

    // Ruta para obtener datos de usuario (protegida más tarde con JWT)
    // Por ahora, cualquiera puede acceder si conoce el ID
    //r.Get("/users/{userID}", handlers.GetUserHandler(db))


    // Iniciar servidor
    port := ":3000"
    log.Printf("Servidor escuchando en puerto %s", port)
    log.Fatal(http.ListenAndServe(port, r))
}

//database

type UserModel struct {
    Username string `json:"username"`
    Password string `json:"password"` // Needed from the client request
}

// setupDatabase inicializa la conexión a la BD
func setupDatabase(dbPath string) (*sql.DB, error) {
    log.Printf("Conectando a la base de datos en: %s", dbPath)
    // Nota: Con modernc.org/sqlite necesitamos el prefijo "file:" y el nombre del driver es "sqlite"
    db, err := sql.Open("sqlite", "file:"+dbPath+"?_foreign_keys=on")
    if err != nil {
        return nil, err
    }

    // Es buena idea hacer ping para verificar la conexión inmediatamente
    if err = db.Ping(); err != nil {
        db.Close() // Cerrar si el ping falla
        return nil, err
    }
    log.Println("Base de datos conectada exitosamente.")
    // Podríamos añadir aquí la creación de tablas si no existen
    // _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (...)`)

    return db, nil
}

//cors

// configureCORS retorna un middleware de CORS configurado
func configureCORS() func(http.Handler) http.Handler {
    // Configuración básica - ¡Ajustar en producción!
    corsMiddleware := cors.New(cors.Options{
        // Permitir orígenes específicos (ej. donde corre su frontend)
        // Usar "*" es inseguro para producción.
        AllowedOrigins:   []string{"*", "http://localhost:5500", "http://127.0.0.1:5500"}, // Añadir origen de Live Server si lo usan
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
        ExposedHeaders:   []string{"Link"},
        AllowCredentials: true, // Importante si usan cookies o auth headers
        MaxAge:           300, // Maximum value not ignored by any of major browsers
    })
    return corsMiddleware.Handler
}