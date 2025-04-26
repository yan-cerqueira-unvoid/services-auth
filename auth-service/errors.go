package main

// Error messages
const (
	// Authentication errors
	ErrInvalidLoginData     = "Invalid login credentials"
	ErrInvalidRegisterData  = "Invalid registration data"
	ErrUserNotFound         = "User not found"
	ErrInvalidCredentials   = "Invalid username or password"
	ErrUsernameAlreadyTaken = "Username already taken"
	ErrPasswordHashFailed   = "Failed to hash password"
	
	// JWT errors
	ErrTokenNotProvided     = "Authentication token not provided"
	ErrInvalidToken         = "Invalid or expired token"
	ErrTokenGenerationFailed = "Failed to generate authentication token"
	ErrUnexpectedSigningMethod = "Unexpected signing method"
	
	// MongoDB errors
	ErrMongoConnection      = "Failed to connect to MongoDB"
	ErrMongoPing            = "Failed to ping MongoDB"
	ErrMongoUserInsert      = "Failed to insert user to database"
	ErrMongoUserFind        = "Failed to find user in database"
	
	// Server errors
	ErrServerStart          = "Failed to start server"
	ErrProcessingRequest    = "Failed to process request"
	ErrInternalServer       = "Internal server error"
)
