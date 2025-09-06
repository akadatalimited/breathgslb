package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// APIServer handles API requests with JWT authentication
type APIServer struct {
	mu         sync.RWMutex
	managerUUID string
	jwtSecret  []byte
	aesKey     []byte
}

// NewAPIServer creates a new API server instance
func NewAPIServer(managerUUID string, jwtSecret []byte, aesKey []byte) *APIServer {
	return &APIServer{
		managerUUID: managerUUID,
		jwtSecret:   jwtSecret,
		aesKey:      aesKey,
	}
}

// Claims represents JWT claims
type Claims struct {
	UserUUID string   `json:"user_uuid"`
	Email    string   `json:"email"`
	Role     string   `json:"role"`
	Scopes   []string `json:"scopes"`
	jwt.RegisteredClaims
}

// ValidateJWT validates a JWT token and returns the claims
func (s *APIServer) ValidateJWT(tokenString string) (*Claims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

// GenerateJWT generates a JWT token for a user
func (s *APIServer) GenerateJWT(userUUID, email, role string, scopes []string) (string, error) {
	// Create claims
	claims := &Claims{
		UserUUID: userUUID,
		Email:    email,
		Role:     role,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userUUID,
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

// AuthenticateAPIKey authenticates an API key and returns the user UUID
func (s *APIServer) AuthenticateAPIKey(apiKey string) (string, []string, error) {
	// In a real implementation, you would:
	// 1. Look up the API key in a database
	// 2. Validate the key
	// 3. Return the user UUID and permissions
	
	// For now, we'll just return a mock response
	// In a real implementation, you would check against stored API keys
	
	// Mock implementation - in reality this would check against a database
	userUUID := "123e4567-e89b-12d3-a456-426614174000"
	permissions := []string{"read", "write"}
	
	return userUUID, permissions, nil
}

// IsManager checks if a user is a manager
func (s *APIServer) IsManager(userUUID string) bool {
	return userUUID == s.managerUUID
}

// GenerateAPIKey generates a new API key
func (s *APIServer) GenerateAPIKey() (string, error) {
	// Generate a new API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate API key: %v", err)
	}
	
	// Encode to base64 for easy transport/storage
	key := base64.URLEncoding.EncodeToString(keyBytes)
	return key, nil
}

// HashAPIKey hashes an API key for secure storage
func (s *APIServer) HashAPIKey(key string) (string, error) {
	// Hash the key using bcrypt for secure storage
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash API key: %v", err)
	}
	
	return string(hashedKey), nil
}

// ValidateHashedAPIKey validates a hashed API key
func (s *APIServer) ValidateHashedAPIKey(key, hashedKey string) bool {
	// Compare the key with its hash
	err := bcrypt.CompareHashAndPassword([]byte(hashedKey), []byte(key))
	return err == nil
}