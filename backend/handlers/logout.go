package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"myapp/models"
	"myapp/utils"
)

func PostLogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Leer el token de la cabecera Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			response := models.NewErrorResponse("Missing or invalid Authorization header")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// 2. Validar el token (aunque no usemos el userID, sirve para comprobar que es válido)
		_, err := utils.ValidateJWT(token)
		if err != nil {
			log.Printf("Invalid token on logout: %v", err)
			response := models.NewErrorResponse("Invalid token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 3. Calcular el hash del token y eliminarlo de la base de datos
		tokenHash := utils.HashToken(token)

		result, err := db.ExecContext(r.Context(), `
			DELETE FROM tokens WHERE token_hash = ?
		`, tokenHash)
		if err != nil {
			log.Printf("Failed to delete token from DB: %v", err)
			response := models.NewErrorResponse("Internal server error")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			log.Printf("Token not found in DB")
		}

		// 4. Éxito
		response := models.NewSuccessResponse("Logout successful")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
