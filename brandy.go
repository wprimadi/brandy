package brandy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gin-gonic/gin"
)

// Waf returns a Gin middleware that implements Coraza WAF.
// This middleware performs request filtering based on the ruleset defined in the Coraza WAF.
func Waf(rulesetPath, logPath, errorPagePath403, errorPagePath500 string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Initialize the WAF engine with a set of security rules.
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithErrorCallback(logError).WithDirectivesFromFile(rulesetPath))
		if err != nil {
			// Log the error and return a response to indicate failure to initialize the WAF.
			logErrorToConsole(fmt.Sprintf("Failed to initialize Coraza WAF engine: %v", err))
			handleErrorAction(c, http.StatusInternalServerError, errorPagePath500, errors.New("failed to initialize Coraza WAF engine"))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Create a new WAF transaction to process the request.
		tx := waf.NewTransaction()
		defer func() {
			// Ensure logging and proper closure of the transaction after request processing.
			tx.ProcessLogging()
			tx.Close()
		}()

		// Extract and parse client IP and port from the request.
		clientIP := c.ClientIP()
		remoteAddr := c.Request.RemoteAddr
		ip, port, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			// Default to "0" if unable to parse the port.
			ip = remoteAddr
			port = "0"
		}

		// Convert the port from string to integer to match the required type for ProcessConnection.
		intPort, err := strconv.Atoi(port)
		if err != nil {
			// Default to 0 if conversion fails.
			intPort = 0
		}

		// Process connection with client and server IPs and port information.
		tx.ProcessConnection(clientIP, intPort, ip, 12345)

		// Process request headers and check for any potential interruption (blocked request).
		it := tx.ProcessRequestHeaders()
		if it != nil {
			// Log the blocked request and provide an appropriate error response.
			matched := tx.MatchedRules()
			logError(matched[0])
			handleErrorAction(c, http.StatusForbidden, errorPagePath403, fmt.Errorf("request blocked by WAF. Status: %d", it.Status))
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Process request body and check for any potential interruption (blocked request).
		it, err = tx.ProcessRequestBody()
		if err != nil {
			logErrorToConsole(err.Error())
			return
		}
		if it != nil {
			// Log the blocked request and provide an appropriate error response.
			matched := tx.MatchedRules()
			logError(matched[0])
			handleErrorAction(c, http.StatusForbidden, errorPagePath403, fmt.Errorf("request blocked by WAF. Status: %d", it.Status))
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Proceed to the next middleware/handler if no issues are encountered.
		c.Next()
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

// logError logs errors in the system. This can be used to capture WAF processing errors.
func logError(error types.MatchedRule) {
	// Log the error to the console using the standard log package (compatible with journalctl and Gin's default logging).
	logMessage := fmt.Sprintf("Error: Request blocked! Rule ID: %v, Rule File: %s, Rule Line: %v, Severity: %s",
		error.Rule().ID(), error.Rule().File(), error.Rule().Line(), error.Rule().Severity())

	logErrorToConsole(logMessage)
	logErrorToConsole(error.ErrorLog())
	logErrorToConsole(error.Rule().Raw())
}

// logErrorToConsole logs system error to the console using the standard log package.
func logErrorToConsole(msg string) {
	// Ensure all log messages are consistent and provide a timestamp.
	fmt.Printf("[WAF Error]: %s\n", msg)
}
