package main

import (
	"api-service/controllers"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	logger.SetOutput(os.Stdout)
	logLevel := os.Getenv("LOG_LEVEL")

	if logLevel == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	
	logger.SetFormatter(&logrus.JSONFormatter{})

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(logMiddleware())
	
	prometheusController := controllers.NewPrometheusController(logger)
	
	r.GET("/metrics", prometheusController.HandleMain())
	r.GET("/health", healthCheck)
	r.GET("/ping", ping)
	
	protected := r.Group("/api")
	protected.GET("/data", getData)
	protected.GET("/metrics", prometheusController.HandleMain())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	logger.Infof("API Service starting on port %s", port)
	if err := r.Run(fmt.Sprintf(":%s", port)); err != nil {
		logger.WithError(err).Fatal(ErrServerStart)
	}
}

func logMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method
		
		c.Next()
		
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

func ping(c *gin.Context) {
	logger.Debug("Ping request received")
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func getData(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	userRole := c.GetHeader("X-User-Role")
	
	if userID == "" {
		logger.Error(ErrUnauthorized)
		c.JSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized})
		return
	}
	
	logger.WithFields(logrus.Fields{
		"userID": userID,
		"role":   userRole,
	}).Info("User accessed protected data")
	
	c.JSON(http.StatusOK, gin.H{
		"data": "Protected data",
		"userID": userID,
		"role": userRole,
	})
}
