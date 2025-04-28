package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOAuthConfig *oauth2.Config
	oauthStateString  string
)

// OAuthUserInfo stores information returned from OAuth providers
type OAuthUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func initOAuth() {
	// Generate a random state string
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logger.WithError(err).Fatal("Failed to generate random state string")
	}
	oauthStateString = base64.StdEncoding.EncodeToString(b)

	// Configure OAuth
	googleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	if googleOAuthConfig.ClientID == "" || googleOAuthConfig.ClientSecret == "" {
		logger.Warn("Google OAuth credentials not configured correctly")
	} else {
		logger.Info("Google OAuth initialized successfully")
	}
}

func googleLoginHandler(c *gin.Context) {
	url := googleOAuthConfig.AuthCodeURL(oauthStateString)

	c.JSON(http.StatusOK, gin.H{"url": url})
}

func googleCallbackHandler(c *gin.Context) {
	// Verify state to prevent CSRF
	state := c.Query("state")
	if state != oauthStateString {
		logger.WithField("received_state", state).Error("Invalid OAuth state")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OAuth state"})
		return
	}

	code := c.Query("code")
	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		logger.WithError(err).Error("Code exchange failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code exchange failed"})
		return
	}

	userInfo, err := getUserInfoFromGoogle(token.AccessToken)
	if err != nil {
		logger.WithError(err).Error("Failed to get user info from Google")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// Check if user exists, if not, create a new one
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err = collection.FindOne(ctx, bson.M{"username": userInfo.Email}).Decode(&user)
	if err != nil {
		// User doesn't exist, create one
		user = User{
			Username: userInfo.Email,
			// Generate a random password since they'll log in with OAuth
			Password: generateRandomPassword(),
			Role:     "user", // Default role
		}

		res, err := collection.InsertOne(ctx, user)
		if err != nil {
			logger.WithError(err).Error(ErrMongoUserInsert)
			c.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServer})
			return
		}

		user.ID = res.InsertedID.(primitive.ObjectID)
		logger.WithFields(logrus.Fields{
			"userID":   user.ID.Hex(),
			"username": user.Username,
		}).Info("New OAuth user registered")
	}

	// Generate JWT
	tokenExpiry := os.Getenv("TOKEN_EXPIRY")
	if tokenExpiry == "" {
		tokenExpiry = "24h"
	}

	expiryDuration, err := time.ParseDuration(tokenExpiry)
	if err != nil {
		expiryDuration = 24 * time.Hour
	}

	claims := jwt.MapClaims{
		"id":       user.ID.Hex(),
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(expiryDuration).Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte(jwtSecret))
	
	if err != nil {
		logger.WithError(err).Error(ErrTokenGenerationFailed)
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServer})
		return
	}

	// Return the JWT and redirect information
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:8002"
	}

	redirectURL := fmt.Sprintf("%s/auth-success?token=%s", frontendURL, tokenString)
	c.JSON(http.StatusOK, gin.H{
		"token":        tokenString,
		"redirect_url": redirectURL,
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func getUserInfoFromGoogle(accessToken string) (*OAuthUserInfo, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken)
	if err != nil {
		return nil, err
	}
	
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo OAuthUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}
	
	return &userInfo, nil
}

func generateRandomPassword() string {
	b := make([]byte, 16) // 16 bytes = 128 bits
	if _, err := rand.Read(b); err != nil {
		return "defaultpassword123"
	}
	
	return base64.StdEncoding.EncodeToString(b)
}
