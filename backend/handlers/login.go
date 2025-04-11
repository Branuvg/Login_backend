package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"
	"myapp/models"
	"myapp/utils" // importa tu archivo jwt_utils.go

	"golang.org/x/crypto/bcrypt"
)


func PostLoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding login request: %v", err)
			response := models.NewErrorResponse("Invalid request body")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}

		if req.Username == "" || req.Password == "" {
			response := models.NewErrorResponse("Username and password are required")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}

		var storedHash string
		var userID int64
		err := db.QueryRowContext(r.Context(),
			"SELECT id, password_hash FROM users WHERE username = ?",
			req.Username,
		).Scan(&userID, &storedHash)

		if err != nil {
			response := models.NewErrorResponse("Invalid username or password")
			statusCode := http.StatusUnauthorized

			if err != sql.ErrNoRows {
				log.Printf("Error querying user '%s': %v", req.Username, err)
				response = models.NewErrorResponse("Internal server error")
				statusCode = http.StatusInternalServerError
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(response)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
			response := models.NewErrorResponse("Invalid username or password")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}

		// ✅ Login successful – Generate JWT
		token, err := utils.GenerateJWT(int(userID))
		if err != nil {
			log.Printf("Error generating JWT: %v", err)
			response := models.NewErrorResponse("Failed to generate token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		tokenHash := utils.HashToken(token)
		expiresAt := time.Now().Add(24 * time.Hour)

		_, err = db.ExecContext(r.Context(),
			"INSERT INTO tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
			userID, tokenHash, expiresAt,
		)
		if err != nil {
			log.Printf("Error saving token hash to DB: %v", err)
			response := models.NewErrorResponse("Failed to store token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		log.Printf("Login successful for user ID: %d (%s)", userID, req.Username)

		// Nuevo DTO de éxito: solo devuelve el token y username
		loginData := models.LoginSuccessData{
			Token:    token,
			Username: req.Username,
		}

		response := models.NewSuccessResponse(loginData)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}