package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	// Import your models package (adjust path 'myapp' if needed)
	"myapp/models"

	// Usar modernc.org/sqlite en lugar de github.com/mattn/go-sqlite3
	_ "modernc.org/sqlite"
	
	"golang.org/x/crypto/bcrypt"
)

// postRegisterHandler handles new user registration attempts.
func PostRegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Decode Request Body into RegisterRequest DTO
		var req models.RegisterRequest // Use DTO from models package
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding register request: %v", err)
			response := models.NewErrorResponse("Invalid request body")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 2. Basic Validation
		if req.Username == "" || req.Password == "" {
			response := models.NewErrorResponse("Username and password cannot be empty")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
			return
		}
		// Add more validation here if needed (e.g., password length)

		// 3. Hash the Password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password for user %s: %v", req.Username, err)
			response := models.NewErrorResponse("Internal server error during registration setup")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 4. Insert User into Database
		// We use ExecContext for context propagation and get the result
		result, err := db.ExecContext(r.Context(),
			"INSERT INTO users(username, password_hash) VALUES(?, ?)",
			req.Username, string(hashedPassword),
		)

		if err != nil {
			// Default error response
			response := models.NewErrorResponse("Failed to register user")
			statusCode := http.StatusInternalServerError

			// Check for UNIQUE constraint error by inspecting the error message
			// modernc.org/sqlite returns error messages that we need to parse
			if isUniqueConstraintError(err) {
				response = models.NewErrorResponse("Username already in use")
				statusCode = http.StatusConflict // 409 Conflict is appropriate
			} else {
				// Log other database errors
				log.Printf("Error inserting user %s: %v", req.Username, err)
				// Keep the generic internal server error message for the client
				response = models.NewErrorResponse("Internal server error")
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 5. Get the ID of the newly inserted user
		userID, err := result.LastInsertId()
		if err != nil {
			// This is less likely, but handle it just in case
			log.Printf("Error getting last insert ID after registering user %s: %v", req.Username, err)
			// Send a success response but maybe log that we couldn't get the ID
			response := models.NewErrorResponse("Registration partially successful, but failed to retrieve user ID")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError) // Or maybe 201 still? Debatable.
			json.NewEncoder(w).Encode(response)
			return
		}

		// 6. Registration Successful - Prepare and Send Success Response
		log.Printf("User '%s' (ID: %d) registered successfully.", req.Username, userID)

		// Create the specific data payload for the success response
		registerData := models.RegisterSuccessData{
			UserID:   userID,
			Username: req.Username,
		}

		// Wrap the data in the standard APIResponse using the factory
		response := models.NewSuccessResponse(registerData)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // 201 Created is the correct status code
		json.NewEncoder(w).Encode(response)
	}
}

// isUniqueConstraintError checks if the error is a UNIQUE constraint violation
// by examining the error message since modernc.org/sqlite doesn't expose error types like mattn/go-sqlite3 does
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "unique constraint") ||
		strings.Contains(errMsg, "constraint failed") ||
		strings.Contains(errMsg, "constraint violation") ||
		strings.Contains(errMsg, "duplicate") ||
		strings.Contains(errMsg, "unique") && strings.Contains(errMsg, "fail")
}

// Para la inicialización de la base de datos, puedes usar algo como esto:
// Note: This part might be in a different file, like main.go or db.go

// InitDB initializes the SQLite database connection
func InitDB(dbPath string) (*sql.DB, error) {
	// El DSN para modernc.org/sqlite requiere el prefijo "file:"
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	
	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, err
	}
	
	// Initialize schema if needed
	if err := initSchema(db); err != nil {
		return nil, err
	}
	
	return db, nil
}

// initSchema creates the necessary tables if they don't exist
func initSchema(db *sql.DB) error {
	// Create users table
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	
	return err
}