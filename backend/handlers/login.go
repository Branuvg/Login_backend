package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type UserModel struct {
	Username string `json:"username"`
	Password string `json:"password"` // Needed from the client request
}

// postLoginHandler maneja el login y genera un JWT si el login es exitoso.
func PostLoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds UserModel
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, `{"error": "Cuerpo de solicitud inválido"}`, http.StatusBadRequest)
			return
		}

		if creds.Username == "" || creds.Password == "" {
			http.Error(w, `{"error": "Usuario y contraseña requeridos"}`, http.StatusBadRequest)
			return
		}
		log.Print("algo30")

		var storedHash string
		var userID int
		err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", creds.Username).Scan(&userID, &storedHash)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, `{"error": "Usuario o contraseña inválidos"}`, http.StatusUnauthorized)
			} else {
				log.Printf("Error consultando usuario '%s': %v", creds.Username, err)
				http.Error(w, `{"error": "Error interno del servidor"}`, http.StatusInternalServerError)
			}
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
			http.Error(w, `{"error": "Usuario o contraseña inválidos"}`, http.StatusUnauthorized)
			return
		}

		// Autenticación exitosa, generar el token
		tokenString, expiresAt, err := GenerateJWT(userID)
		if err != nil {
			log.Printf("Error generando JWT para el usuario %d: %v", userID, err)
			http.Error(w, `{"error": "Error generando sesión"}`, http.StatusInternalServerError)
			return
		}

		// Guardar el token en la base de datos
		if err := StoreToken(db, userID, tokenString, expiresAt); err != nil {
			log.Printf("Error guardando token para el usuario %d: %v", userID, err)
			http.Error(w, `{"error": "Error guardando sesión"}`, http.StatusInternalServerError)
			return
		}

		log.Printf("Login exitoso para el usuario %d (%s)", userID, creds.Username)

		// Responder con el token JWT
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
		})
	}
}
