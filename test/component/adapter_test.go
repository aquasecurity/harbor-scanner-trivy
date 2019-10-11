// +build component

package component

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestAdapter is a component test for the whole adapter service.
// It should test only the shortest and happiest path to make sure that all pieces are nicely put together.
func TestAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("A component test")
	}
	// TODO Implement component test:
	// 1. Spin up adapter service and its dependencies (Redis + Docker Registry)
	// 2. Use an HTTP client to
	//    1. Send a simple valid scan request
	//    2. Poll for scan report until you get scan report
	// This will simulate Harbor calling the adapter.
	// Use docker-sdk / docker-compose / testcontainers-go / etc.
	assert.True(t, true)
}
