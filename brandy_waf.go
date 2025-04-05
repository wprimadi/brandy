package brandy

import (
	"github.com/corazawaf/coraza/v3/types"
)

type WAFEngine interface {
	NewTransaction() WAFTransaction
}

type WAFTransaction interface {
	ProcessURI(uri, method, httpVersion string)
	ProcessRequestHeaders() *types.Interruption
	ProcessRequestBody() (*types.Interruption, error)
	ProcessResponseHeaders(statusCode int, proto string) *types.Interruption
	ProcessResponseBody() (*types.Interruption, error)
	Interrupt() *types.Interruption
	Close()
}
