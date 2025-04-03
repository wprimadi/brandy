# Brandy

![Brandy](https://10thwhiskey.com/cdn/shop/products/Final_BrandyBottle_Mockup_1100x.png?v=1644260369)

![Go Version](https://img.shields.io/github/go-mod/go-version/wprimadi/brandy) 
![License](https://img.shields.io/github/license/wprimadi/brandy) 
![Last Commit](https://img.shields.io/github/last-commit/wprimadi/brandy) 
![Go Report Card](https://goreportcard.com/badge/github.com/wprimadi/brandy) 
![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=wprimadi_brandy&metric=alert_status) 
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-blue)

Brandy (Blocking Request Anomalies & Network Defense Yielder) a middleware for Gin framework! This project provides a middleware for the Gin framework that integrates the Coraza Web Application Firewall (WAF). The middleware enhances security by filtering incoming requests based on predefined rules.

## Features
✅ Implements Coraza WAF for request filtering.  
✅ Logs detected threats to the console (compatible with `journalctl`).  
✅ Blocks malicious requests based on predefined rules.  
✅ Supports custom error pages for blocked requests.  
✅ Compatible with standard middleware practices in Gin.  

## Installation
```sh
go get -u github.com/wprimadi/brandy
```

## Usage

### Middleware Integration in Gin

Create a `main.go` file and use the middleware:

```go
func main() {
	// Define WAF configuration
	rulesetPath := "rules/ruleset.conf" // Ruleset file
	errorPagePath403 := "" // Custom 403 error page
	errorPagePath500 := "" // Custom 500 error page

	// Initialize Gin router with default middleware (Logger and Recovery)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Apply WAF middleware
	router.Use(middleware.ModSecurityMiddleware(rulesetPath, errorPagePath403, errorPagePath500))

	// Define routes
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Welcome to the secure API!"})
	})

	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "This route is protected by WAF"})
	})

	// Start the server
	log.Println("Starting server on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```