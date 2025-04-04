package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Estructura del usuario que recibiremos
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// PostRegisterHandler maneja la solicitud de registro
func PostRegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Formato JSON inválido", http.StatusBadRequest)
			return
		}

		// Hash de la contraseña antes de guardarla
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error al generar hash", http.StatusInternalServerError)
			return
		}

		// Insertar en la base de datos
		_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", req.Username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Error al registrar usuario", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Usuario registrado exitosamente"))
	}
}
