package brandy

import (
	"fmt"
	"log"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type Engine struct {
	engine coraza.WAF
}

func InitWaf(rulesetPaths []string) (*Engine, error) {
	// Initialize the WAF engine with a set of security rules.
	wafConfig := coraza.NewWAFConfig().WithErrorCallback(logError)

	// Load rulesets based on provided file paths.
	for _, path := range rulesetPaths {
		wafConfig.WithDirectivesFromFile(path)
	}

	// Initialize WAF with loaded rulesets.
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		// Log the error and return to indicate failure to initialize the WAF.
		return &Engine{engine: nil}, err
	}

	return &Engine{engine: waf}, nil
}

type CorazaTx struct {
	tx types.Transaction
}

func (c *Engine) NewTransaction() WAFTransaction {
	return &CorazaTx{tx: c.engine.NewTransaction()}
}

func (t *CorazaTx) ProcessURI(uri, method, httpVersion string) {
	t.tx.ProcessURI(uri, method, httpVersion)
}

func (t *CorazaTx) ProcessRequestHeaders() *types.Interruption {
	return t.tx.ProcessRequestHeaders()
}
func (t *CorazaTx) ProcessRequestBody() (*types.Interruption, error) {
	return t.tx.ProcessRequestBody()
}
func (t *CorazaTx) ProcessResponseHeaders(statusCode int, proto string) *types.Interruption {
	return t.tx.ProcessResponseHeaders(statusCode, proto)
}
func (t *CorazaTx) ProcessResponseBody() (*types.Interruption, error) {
	return t.tx.ProcessResponseBody()
}
func (t *CorazaTx) Interrupt() *types.Interruption {
	return t.tx.Interruption()
}
func (t *CorazaTx) Close() {
	t.tx.Close()
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
	log.Printf("[WAF Error]: %s\n", msg)
}
