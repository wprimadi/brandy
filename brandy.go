package brandy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// Waf returns a Gin middleware that implements Coraza WAF.
// This middleware performs request filtering based on the ruleset defined in the Coraza WAF.
func Waf(engine WAFEngine, errorPagePath403 string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tx := engine.NewTransaction()
		defer tx.Close()

		// Check URI, Method, and HTTP Version
		tx.ProcessURI(c.Request.RequestURI, c.Request.Method, c.Request.Proto)
		c.Request.Header.Del("Content-Length") // Optional sanitization
		for k, v := range c.Request.Header {
			c.Request.Header[k] = v
		}
		_ = tx.ProcessRequestHeaders()

		if c.Request.Body != nil {
			body, _ := io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
			tx.ProcessRequestBody()
		}

		if it := tx.Interrupt(); it != nil {
			// Log the blocked request and provide an appropriate error response.
			log.Printf("Request blocked! Action: %s, Rule ID: %v, Status: %v", it.Action, it.RuleID, it.Status)
			log.Printf("%s", it.Data)

			handleErrorAction(c, it.Status, errorPagePath403, fmt.Errorf("request blocked with rule ID %v", it.RuleID))
			c.AbortWithStatus(it.Status)
			return
		}

		// Proceed to the next middleware/handler if no issues are encountered.
		c.Next()

		tx.ProcessResponseHeaders(c.Writer.Status(), c.Request.Proto)
		tx.ProcessResponseBody()
	}
}

// handleErrorAction handles error responses for blocked requests, either by serving an HTML page or returning a JSON error.
func handleErrorAction(c *gin.Context, statusCode int, errorPagePath string, err error) {
	// If an error page exists, serve it to the user.
	if strings.TrimSpace(errorPagePath) != "" {
		if _, err := os.Stat(errorPagePath); err == nil {
			// Serve the error page if it exists.
			http.ServeFile(c.Writer, c.Request, errorPagePath)
		} else {
			// Fallback to JSON error response if the error page is missing.
			c.JSON(statusCode, gin.H{"error": err.Error()})
		}
	} else {
		// Default JSON response for blocked requests.
		c.JSON(statusCode, gin.H{"error": err.Error()})
	}
}
