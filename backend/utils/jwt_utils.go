package utils

import (
    "time"
    "os"
    "github.com/golang-jwt/jwt/v5"
    "crypto/sha256"
    "encoding/hex"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET")) // Define esta variable de entorno

type Claims struct {
    UserID int `json:"user_id"`
    jwt.RegisteredClaims
}

// Genera un token JWT para el usuario
func GenerateJWT(userID int) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)

    claims := &Claims{
        UserID: userID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

// Verifica y devuelve los claims del token
func ValidateJWT(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }

    return nil, err
}

// Devuelve un hash del token (para guardar en DB)
func HashToken(token string) string {
    hash := sha256.Sum256([]byte(token))
    return hex.EncodeToString(hash[:])
}
