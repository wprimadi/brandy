# Brandy

![Brandy](https://10thwhiskey.com/cdn/shop/products/Final_BrandyBottle_Mockup_300x.png?v=1644260369)

![Go Version](https://img.shields.io/github/go-mod/go-version/wprimadi/brandy) 
![License](https://img.shields.io/github/license/wprimadi/brandy) 
![Last Commit](https://img.shields.io/github/last-commit/wprimadi/brandy) 
![Go Report Card](https://goreportcard.com/badge/github.com/wprimadi/brandy) 
![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=wprimadi_brandy&metric=alert_status) 
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-blue)

**Brandy** (Blocking Request Anomalies & Network Defense Yielder) is a security middleware for the [Gin](https://github.com/gin-gonic/gin) web framework. It provides a layer of HTTP request filtering based on customizable rulesets to help detect and block malicious traffic patterns before they reach your application.

---

## Features
✅ Implements Coraza WAF for request filtering.  
✅ Logs detected threats to the console (compatible with `journalctl`).  
✅ Blocks malicious requests based on predefined rules.  
✅ Supports custom error pages for blocked requests.  
✅ Compatible with standard middleware practices in Gin. 

---

## Installation
```go
go get -u github.com/wprimadi/brandy@v1.0.1
```

or

```go
go get -u github.com/wprimadi/brandy@latest
```

---

## Usage

### Middleware Integration in Gin

Create a `main.go` file and use the middleware:

```go
package main

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/wprimadi/brandy"
)

func main() {
	// Define WAF configuration
	rulesetPaths := []string{
		"rulesets/default.conf",
		"rulesets/owasp-crs/rules/*.conf",
	}
	errorPagePath403 := "" // Custom 403 error page

	// Initialize Gin router with default middleware (Logger and Recovery)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Init WAF engine and load rulesets
	waf, err := brandy.InitWaf(rulesetPaths)
	if err != nil {
		log.Fatalf("failed to load waf: %v", err)
	}

	// Apply WAF middleware
	router.Use(brandy.Waf(waf, errorPagePath403))

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

---

## Performance Notes
- Use minimal, targeted rules for better performance.
- Avoid overly broad regexes.
- Always test with real traffic to fine-tune rule impact.

---

## Supported Rulesets

This middleware supports rule definitions written in ModSecurity/Coraza syntax. It includes a `rulesets` folder in the repository that contains community and custom-modified rulesets based on:

- **Coraza default rules**
- **ModSecurity's OWASP Core Rule Set (CRS)**

These rulesets have been optimized and adjusted to work well within the Gin middleware environment, and serve as a great starting point for implementing robust application-layer protection.

---

## License

This project is open-source and available under the MIT License.
