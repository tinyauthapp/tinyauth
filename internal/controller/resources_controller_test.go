package controller_test

import (
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourcesController(t *testing.T) {
	tlog.NewTestLogger().Init()
	tempDir := t.TempDir()

	resourcesControllerCfg := controller.ResourcesControllerConfig{
		Path:    path.Join(tempDir, "resources"),
		Enabled: true,
	}

	err := os.Mkdir(resourcesControllerCfg.Path, 0777)
	require.NoError(t, err)

	type testCase struct {
		description string
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Ensure resources endpoint returns 200 OK for existing file",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/resources/testfile.txt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "This is a test file.", recorder.Body.String())
			},
		},
		{
			description: "Ensure resources endpoint returns 404 Not Found for non-existing file",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/resources/nonexistent.txt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 404, recorder.Code)
			},
		},
		{
			description: "Ensure resources controller denies path traversal",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/resources/../somefile.txt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 404, recorder.Code)
			},
		},
	}

	testFilePath := resourcesControllerCfg.Path + "/testfile.txt"
	err = os.WriteFile(testFilePath, []byte("This is a test file."), 0777)
	require.NoError(t, err)

	testFilePathParent := tempDir + "/somefile.txt"
	err = os.WriteFile(testFilePathParent, []byte("This file should not be accessible."), 0777)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			group := router.Group("/")
			gin.SetMode(gin.TestMode)

			resourcesController := controller.NewResourcesController(resourcesControllerCfg, group)
			resourcesController.SetupRoutes()

			recorder := httptest.NewRecorder()
			test.run(t, router, recorder)
		})
	}
}
