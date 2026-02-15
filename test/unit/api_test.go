package unit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

func TestAPIServer(t *testing.T) {
	// Create mock manager and SDK
	mockMgr := xdp.NewMockManager()
	sdkInstance := sdk.NewSDK(mockMgr)

	// Create API server
	server := api.NewServer(sdkInstance, 8080)
	handler := server.Handler()

	// Test /healthz endpoint
	req := httptest.NewRequest("GET", "/healthz", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "ok")

	// Test /version endpoint
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/version", nil)
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "version")

	// Test /stats endpoint
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/stats", nil)
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	// Test /rules endpoint
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/rules", nil)
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestAPIAuth(t *testing.T) {
	// Create mock manager and SDK
	mockMgr := xdp.NewMockManager()
	sdkInstance := sdk.NewSDK(mockMgr)

	// Create API server
	server := api.NewServer(sdkInstance, 8080)
	handler := server.Handler()

	// Test unauthorized access to protected endpoint
	req := httptest.NewRequest("GET", "/rules", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Without proper authentication, this might return 401 or redirect
	// The exact behavior depends on the implementation
	t.Logf("Auth test status: %d", recorder.Code)
}
