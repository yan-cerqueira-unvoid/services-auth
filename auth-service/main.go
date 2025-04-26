package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	logger     = logrus.New()
	client     *mongo.Client
	collection *mongo.Collection
	jwtSecret  string
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username string             `bson:"username" json:"username"`
	Password string             `bson:"password" json:"-"`
	Role     string             `bson:"role" json:"role"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

func main() {
	// Configuração de logs
	logger.SetOutput(os.Stdout)
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Configuração JWT
	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default_jwt_secret_change_this"
		logger.Warn("JWT_SECRET not configured, using default value")
	}

	// Conexão com MongoDB
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017/auth"
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var err error
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		logger.WithError(err).Fatal(ErrMongoConnection)
	}
	
	// Verificar conexão
	err = client.Ping(ctx, nil)
	if err != nil {
		logger.WithError(err).Fatal(ErrMongoPing)
	}
	
	logger.Info("Successfully connected to MongoDB")
	collection = client.Database("auth").Collection("users")

	// Configuração do Gin
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(logMiddleware())

	// Rotas
	r.GET("/health", healthCheck)
	r.POST("/login", login)
	r.POST("/register", register)
	r.GET("/validate", validateToken)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	logger.Infof("Auth Service starting on port %s", port)
	if err := r.Run(fmt.Sprintf(":%s", port)); err != nil {
		logger.WithError(err).Fatal(ErrServerStart)
	}
}

func logMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Before request
		path := c.Request.URL.Path
		method := c.Request.Method
		
		c.Next()
		
		// After request
		statusCode := c.Writer.Status()
		logger.WithFields(logrus.Fields{
			"path":   path,
			"method": method,
			"status": statusCode,
		}).Info("Request processed")
	}
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "UP",
	})
}

func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WithError(err).Error(ErrInvalidRegisterData)
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRegisterData})
		return
	}

	// Check if user already exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var existingUser User
	err := collection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&existingUser)
	if err == nil {
		logger.WithField("username", req.Username).Error(ErrUsernameAlreadyTaken)
		c.JSON(http.StatusConflict, gin.H{"error": ErrUsernameAlreadyTaken})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.WithError(err).Error(ErrPasswordHashFailed)
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServer})
		return
	}

	// Create new user
	newUser := User{
		Username: req.Username,
		Password: string(hashedPassword),
		Role:     req.Role,
	}

	res, err := collection.InsertOne(ctx, newUser)
	if err != nil {
		logger.WithError(err).Error(ErrMongoUserInsert)
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServer})
		return
	}

	// Return created user ID
	id := res.InsertedID.(primitive.ObjectID)
	logger.WithFields(logrus.Fields{
		"userID":   id.Hex(),
		"username": req.Username,
	}).Info("User registered successfully")
	
	c.JSON(http.StatusCreated, gin.H{
		"id":       id.Hex(),
		"username": req.Username,
		"role":     req.Role,
	})
}

func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WithError(err).Error(ErrInvalidLoginData)
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidLoginData})
		return
	}

	// Find user in database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var user User
	err := collection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		logger.WithField("username", req.Username).Error(ErrUserNotFound)
		c.JSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidCredentials})
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		logger.WithField("username", req.Username).Error(ErrInvalidCredentials)
		c.JSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidCredentials})
		return
	}

	// Generate JWT token
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
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		logger.WithError(err).Error(ErrTokenGenerationFailed)
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServer})
		return
	}

	logger.WithField("username", req.Username).Info("User logged in successfully")
	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func validateToken(c *gin.Context) {
	tokenHeader := c.GetHeader("Authorization")
	if tokenHeader == "" {
		logger.Warn(ErrTokenNotProvided)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Remove "Bearer" prefix if exists
	tokenString := tokenHeader
	if strings.HasPrefix(tokenHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenHeader, "Bearer ")
	}

	// Validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf(ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		logger.WithError(err).Error(ErrInvalidToken)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Valid token, set response headers for ForwardAuth middleware
		userID, _ := claims["id"].(string)
		username, _ := claims["username"].(string)
		role, _ := claims["role"].(string)

		c.Header("X-User-ID", userID)
		c.Header("X-Username", username)
		c.Header("X-User-Role", role)

		logger.WithFields(logrus.Fields{
			"userID":   userID,
			"username": username,
			"role":     role,
		}).Debug("Token validated successfully")
		
		c.Status(http.StatusOK)
	} else {
		logger.Error(ErrInvalidToken)
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}
