package main

const (
	// Server errors
	ErrServerStart        = "Failed to start server"
	ErrInternalServer     = "Internal server error"
	
	// Authentication errors
	ErrUnauthorized       = "Unauthorized access"
	ErrForbidden          = "Access forbidden"
	
	// Request errors
	ErrInvalidRequest     = "Invalid request data"
	ErrResourceNotFound   = "Resource not found"
	
	// External service errors
	ErrAuthServiceUnavailable = "Authentication service unavailable"
)
