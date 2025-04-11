package handlers

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey = []byte("clave_secreta_segura") // Idealmente usar variable de entorno

// ====================
// Funciones principales
// ====================

// Generar token JWT
func GenerateJWT(userID int) (string, time.Time, error) {
    expiration := time.Now().Add(24 * time.Hour)

    claims := &jwt.RegisteredClaims{
        Subject:   fmt.Sprintf("%d", userID),
        ExpiresAt: jwt.NewNumericDate(expiration),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecretKey)
    if err != nil {
        return "", time.Time{}, err
    }

    return tokenString, expiration, nil
}

// Hashear el token
func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return hex.EncodeToString(h[:])
}

// Guardar hash del token en la base de datos
func StoreToken(db *sql.DB, userID int, token string, expiresAt time.Time) error {
    tokenHash := hashToken(token)
    _, err := db.Exec("INSERT INTO tokens(user_id, token_hash, expires_at) VALUES (?, ?, ?)", userID, tokenHash, expiresAt)
    return err
}

// Eliminar token (logout)
func invalidateToken(db *sql.DB, token string) error {
    tokenHash := hashToken(token)
    _, err := db.Exec("DELETE FROM tokens WHERE token_hash = ?", tokenHash)
    return err
}

// Validar token y obtener userID
func validateTokenAndGetUserID(db *sql.DB, tokenStr string) (int, error) {
    claims := &jwt.RegisteredClaims{}
    token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("método de firma no esperado: %v", token.Header["alg"])
        }
        return jwtSecretKey, nil
    })

    if err != nil || !token.Valid {
        return 0, errors.New("token inválido o expirado")
    }

    // Verificación en DB
    tokenHash := hashToken(tokenStr)
    var userID int
    var expires time.Time
    err = db.QueryRow("SELECT user_id, expires_at FROM tokens WHERE token_hash = ?", tokenHash).Scan(&userID, &expires)
    if err != nil {
        return 0, errors.New("token no encontrado en base de datos")
    }

    if time.Now().After(expires) {
        // Limpieza opcional
        go func() {
            _ = cleanupExpiredToken(db, tokenStr)
        }()
        return 0, errors.New("token expirado")
    }

    return userID, nil
}

// ====================
// Middleware JWT
// ====================
func jwtAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            auth := r.Header.Get("Authorization")
            if !strings.HasPrefix(auth, "Bearer ") {
                http.Error(w, "Token faltante o malformado", http.StatusUnauthorized)
                return
            }

            tokenStr := strings.TrimPrefix(auth, "Bearer ")
            userID, err := validateTokenAndGetUserID(db, tokenStr)
            if err != nil {
                http.Error(w, "Token inválido", http.StatusUnauthorized)
                return
            }

            ctx := context.WithValue(r.Context(), "userID", userID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// ====================
// Limpieza de expirados
// ====================
func cleanupExpiredToken(db *sql.DB, token string) error {
    tokenHash := hashToken(token)
    _, err := db.Exec("DELETE FROM tokens WHERE token_hash = ?", tokenHash)
    if err != nil && err != sql.ErrNoRows {
        log.Printf("Error al limpiar token expirado: %v", err)
    }
    return nil
}