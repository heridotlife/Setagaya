package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"

	"github.com/hveda/Setagaya/setagaya/model"
	"github.com/hveda/Setagaya/setagaya/scheduler"
)

func TestHasInvalidDiff(t *testing.T) {
	testCases := []struct {
		name          string
		current       []*model.ExecutionPlan
		updated       []*model.ExecutionPlan
		expectInvalid bool
		expectedMsg   string
	}{
		{
			name: "no changes - valid",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
				{PlanID: 2, Engines: 3, Concurrency: 15},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
				{PlanID: 2, Engines: 3, Concurrency: 15},
			},
			expectInvalid: false,
			expectedMsg:   "",
		},
		{
			name: "different number of plans - invalid",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
				{PlanID: 2, Engines: 3, Concurrency: 15},
			},
			expectInvalid: true,
			expectedMsg:   "You cannot add/remove plans while have engines deployed",
		},
		{
			name: "fewer plans in updated - invalid",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
				{PlanID: 2, Engines: 3, Concurrency: 15},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
			},
			expectInvalid: true,
			expectedMsg:   "You cannot add/remove plans while have engines deployed",
		},
		{
			name: "new plan added - invalid",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
				{PlanID: 3, Engines: 2, Concurrency: 10}, // Different PlanID
			},
			expectInvalid: true,
			expectedMsg:   "You cannot add/remove plans while have engines deployed",
		},
		{
			name: "engine count changed - invalid",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 5, Concurrency: 10}, // Changed engines
			},
			expectInvalid: true,
			expectedMsg:   "You cannot change engine numbers while having engines deployed",
		},
		{
			name: "concurrency changed - invalid",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 20}, // Changed concurrency
			},
			expectInvalid: true,
			expectedMsg:   "You cannot change concurrency while having engines deployed",
		},
		{
			name: "multiple changes - engine count priority",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 5, Concurrency: 20}, // Both changed, but engines checked first
			},
			expectInvalid: true,
			expectedMsg:   "You cannot change engine numbers while having engines deployed",
		},
		{
			name: "allowed changes - duration, rampup, name",
			current: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10, Duration: 60, Rampup: 5, Name: "test1"},
			},
			updated: []*model.ExecutionPlan{
				{PlanID: 1, Engines: 2, Concurrency: 10, Duration: 120, Rampup: 10, Name: "test1-updated"},
			},
			expectInvalid: false,
			expectedMsg:   "",
		},
		{
			name:          "empty current and updated - valid",
			current:       []*model.ExecutionPlan{},
			updated:       []*model.ExecutionPlan{},
			expectInvalid: false,
			expectedMsg:   "",
		},
		{
			name:          "nil current and empty updated - valid",
			current:       nil,
			updated:       []*model.ExecutionPlan{},
			expectInvalid: false,
			expectedMsg:   "",
		},
		{
			name:          "empty current and nil updated - valid",
			current:       []*model.ExecutionPlan{},
			updated:       nil,
			expectInvalid: false,
			expectedMsg:   "",
		},
		{
			name:          "both nil - valid",
			current:       nil,
			updated:       nil,
			expectInvalid: false,
			expectedMsg:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isInvalid, msg := hasInvalidDiff(tc.current, tc.updated)
			assert.Equal(t, tc.expectInvalid, isInvalid)
			if tc.expectInvalid {
				assert.Equal(t, tc.expectedMsg, msg)
			} else {
				assert.Empty(t, msg)
			}
		})
	}
}

func TestHasInvalidDiffComplexScenarios(t *testing.T) {
	t.Run("multiple plans with mixed valid/invalid changes", func(t *testing.T) {
		current := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 2, Concurrency: 10},
			{PlanID: 2, Engines: 3, Concurrency: 15},
			{PlanID: 3, Engines: 1, Concurrency: 5},
		}
		updated := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 2, Concurrency: 10}, // No change
			{PlanID: 2, Engines: 5, Concurrency: 15}, // Engine count changed - should fail
			{PlanID: 3, Engines: 1, Concurrency: 5},  // No change
		}

		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.True(t, isInvalid)
		assert.Equal(t, "You cannot change engine numbers while having engines deployed", msg)
	})

	t.Run("large number of plans", func(t *testing.T) {
		var current, updated []*model.ExecutionPlan

		// Create 100 plans
		for i := int64(1); i <= 100; i++ {
			current = append(current, &model.ExecutionPlan{
				PlanID:      i,
				Engines:     2,
				Concurrency: 10,
			})
			updated = append(updated, &model.ExecutionPlan{
				PlanID:      i,
				Engines:     2,
				Concurrency: 10,
			})
		}

		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.False(t, isInvalid)
		assert.Empty(t, msg)
	})

	t.Run("duplicate plan IDs in current", func(t *testing.T) {
		current := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 2, Concurrency: 10},
			{PlanID: 1, Engines: 3, Concurrency: 15}, // Duplicate PlanID - last one wins in map
		}
		updated := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 2, Concurrency: 10}, // Will be compared against engines: 3, concurrency: 15
			{PlanID: 1, Engines: 3, Concurrency: 15},
		}

		// Function should detect engine mismatch (2 vs 3)
		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.True(t, isInvalid)
		assert.Equal(t, "You cannot change engine numbers while having engines deployed", msg)
	})

	t.Run("zero values", func(t *testing.T) {
		current := []*model.ExecutionPlan{
			{PlanID: 0, Engines: 0, Concurrency: 0},
		}
		updated := []*model.ExecutionPlan{
			{PlanID: 0, Engines: 0, Concurrency: 0},
		}

		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.False(t, isInvalid)
		assert.Empty(t, msg)
	})

	t.Run("negative values", func(t *testing.T) {
		current := []*model.ExecutionPlan{
			{PlanID: -1, Engines: -2, Concurrency: -10},
		}
		updated := []*model.ExecutionPlan{
			{PlanID: -1, Engines: -2, Concurrency: -10},
		}

		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.False(t, isInvalid)
		assert.Empty(t, msg)
	})
}

func TestHasInvalidDiffEdgeCases(t *testing.T) {
	t.Run("order doesn't matter", func(t *testing.T) {
		current := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 2, Concurrency: 10},
			{PlanID: 2, Engines: 3, Concurrency: 15},
		}
		updated := []*model.ExecutionPlan{
			{PlanID: 2, Engines: 3, Concurrency: 15}, // Different order
			{PlanID: 1, Engines: 2, Concurrency: 10},
		}

		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.False(t, isInvalid)
		assert.Empty(t, msg)
	})

	t.Run("checks stop at first invalid difference", func(t *testing.T) {
		current := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 2, Concurrency: 10},
			{PlanID: 2, Engines: 3, Concurrency: 15},
		}
		updated := []*model.ExecutionPlan{
			{PlanID: 1, Engines: 5, Concurrency: 20}, // Both engines and concurrency changed
			{PlanID: 2, Engines: 3, Concurrency: 15},
		}

		isInvalid, msg := hasInvalidDiff(current, updated)
		assert.True(t, isInvalid)
		// Should return engines error (checked first)
		assert.Equal(t, "You cannot change engine numbers while having engines deployed", msg)
	})
}

// Test API helper functions

func TestSetagayaAPI_makeRespMessage(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name     string
		message  string
		expected string
	}{
		{
			name:     "simple message",
			message:  "Operation successful",
			expected: "Operation successful",
		},
		{
			name:     "empty message",
			message:  "",
			expected: "",
		},
		{
			name:     "message with special characters",
			message:  "Error: failed with status 404 & message=\"not found\"",
			expected: "Error: failed with status 404 & message=\"not found\"",
		},
		{
			name:     "long message",
			message:  strings.Repeat("test ", 100),
			expected: strings.Repeat("test ", 100),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := api.makeRespMessage(tc.message)
			assert.NotNil(t, result)
			assert.Equal(t, tc.expected, result.Message)
		})
	}
}

func TestSetagayaAPI_jsonise(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name           string
		status         int
		content        interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "success response",
			status:         http.StatusOK,
			content:        map[string]string{"message": "success"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
		{
			name:           "error response",
			status:         http.StatusBadRequest,
			content:        map[string]string{"error": "bad request"},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"bad request"}`,
		},
		{
			name:           "nil content",
			status:         http.StatusNoContent,
			content:        nil,
			expectedStatus: http.StatusNoContent,
			expectedBody:   "null",
		},
		{
			name:           "JSONMessage struct",
			status:         http.StatusCreated,
			content:        &JSONMessage{Message: "created"},
			expectedStatus: http.StatusCreated,
			expectedBody:   `{"message":"created"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			api.jsonise(w, tc.status, tc.content)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			// Parse and compare JSON to handle formatting differences
			var expected, actual interface{}
			if err := json.Unmarshal([]byte(tc.expectedBody), &expected); err != nil {
				t.Logf("Error unmarshaling expected body: %v", err)
			}
			if err := json.Unmarshal(w.Body.Bytes(), &actual); err != nil {
				t.Logf("Error unmarshaling actual body: %v", err)
			}
			assert.Equal(t, expected, actual)
		})
	}
}

func TestSetagayaAPI_makeFailMessage(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name           string
		message        string
		statusCode     int
		expectedStatus int
	}{
		{
			name:           "bad request",
			message:        "Invalid input",
			statusCode:     http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "not found",
			message:        "Resource not found",
			statusCode:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "internal server error",
			message:        "Something went wrong",
			statusCode:     http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "empty message",
			message:        "",
			statusCode:     http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			api.makeFailMessage(w, tc.message, tc.statusCode)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var response JSONMessage
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tc.message, response.Message)
		})
	}
}

func TestSetagayaAPI_handleErrorsFromExt(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name           string
		inputError     error
		expectNil      bool
		expectedStatus int
		expectedMsg    string
	}{
		{
			name: "DBError",
			inputError: &model.DBError{
				Err:     errors.New("database error"),
				Message: "Database connection failed",
			},
			expectNil:      true,
			expectedStatus: http.StatusNotFound,
			expectedMsg:    "Database connection failed",
		},
		{
			name: "NoResourcesFoundErr",
			inputError: &scheduler.NoResourcesFoundErr{
				Err:     errors.New("no resources"),
				Message: "No available resources",
			},
			expectNil:      true,
			expectedStatus: http.StatusNotFound,
			expectedMsg:    "No available resources",
		},
		{
			name:       "Unknown error type",
			inputError: errors.New("unknown error"),
			expectNil:  false,
		},
		{
			name:       "Nil error",
			inputError: nil,
			expectNil:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			result := api.handleErrorsFromExt(w, tc.inputError)

			if tc.expectNil {
				assert.Nil(t, result)
				assert.Equal(t, tc.expectedStatus, w.Code)

				var response JSONMessage
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMsg, response.Message)
			} else {
				assert.Equal(t, tc.inputError, result)
			}
		})
	}
}

// Test the main API constructor and central error handling
func TestSetagayaAPI_NewAPIServer_Safe(t *testing.T) {
	// Skip this test in environments where config isn't fully set up
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" {
		t.Skip("Skipping NewAPIServer test in test mode (requires full config)")
	}

	api := NewAPIServer()
	assert.NotNil(t, api)
	assert.NotNil(t, api.ctr)
}

// Test jsonise function with various scenarios
func TestSetagayaAPI_Jsonise(t *testing.T) {
	api := &SetagayaAPI{}

	t.Run("successful json encoding", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		data := map[string]string{"message": "test"}

		api.jsonise(recorder, http.StatusOK, data)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Contains(t, recorder.Header().Get("Content-Type"), "application/json")

		var result map[string]string
		err := json.Unmarshal(recorder.Body.Bytes(), &result)
		assert.NoError(t, err)
		assert.Equal(t, "test", result["message"])
	})

	t.Run("handle encoding error with invalid data", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		// Using a function which cannot be encoded to JSON to trigger error
		invalidData := func() {}

		api.jsonise(recorder, http.StatusOK, invalidData)

		assert.Equal(t, http.StatusOK, recorder.Code)
		// Should still set content type even on error
		assert.Contains(t, recorder.Header().Get("Content-Type"), "application/json")
	})
}

// Test makeRespMessage function
func TestMakeRespMessage(t *testing.T) {
	api := &SetagayaAPI{}
	result := api.makeRespMessage("test message")
	expected := &JSONMessage{Message: "test message"}
	assert.Equal(t, expected, result)
}

// Test makeFailMessage function
func TestMakeFailMessage(t *testing.T) {
	api := &SetagayaAPI{}
	recorder := httptest.NewRecorder()

	api.makeFailMessage(recorder, "test failure", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	var response JSONMessage
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test failure", response.Message)
}

// Test handleErrorsFromExt function
func TestHandleErrorsFromExt(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name          string
		err           error
		expectHandled bool
	}{
		{
			name:          "database error",
			err:           &model.DBError{Message: "db connection failed"},
			expectHandled: true,
		},
		{
			name:          "generic error",
			err:           errors.New("some error"),
			expectHandled: false, // Should return the error unhandled
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			unhandledErr := api.handleErrorsFromExt(recorder, tc.err)

			if tc.expectHandled {
				// Error should be handled (status code set)
				assert.True(t, recorder.Code >= 400)
				assert.Nil(t, unhandledErr)
			} else {
				// Error should be returned unhandled
				assert.Equal(t, tc.err, unhandledErr)
			}
		})
	}
}

// Test handleErrors function
func TestSetagayaAPI_HandleErrors(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "login error",
			err:            makeLoginError(),
			expectedStatus: http.StatusForbidden, // Changed to match actual behavior
		},
		{
			name:           "invalid request error",
			err:            makeInvalidRequestError("test field"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "no permission error",
			err:            makeNoPermissionErr("access denied"),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "internal server error",
			err:            makeInternalServerError("test error"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "invalid resource error",
			err:            makeInvalidResourceError("test_id"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "project ownership error",
			err:            makeProjectOwnershipError(),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "collection ownership error",
			err:            makeCollectionOwnershipError(),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			api.handleErrors(recorder, tc.err)

			assert.Equal(t, tc.expectedStatus, recorder.Code)
		})
	}
}

// Test getProject function (unit tests)
func TestGetProject_Unit(t *testing.T) {
	t.Run("empty project ID", func(t *testing.T) {
		_, err := getProject("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "project_id cannot be empty")
	})

	t.Run("invalid project ID format", func(t *testing.T) {
		_, err := getProject("invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})
}

// Test getPlan function (unit tests)
func TestGetPlan_Unit(t *testing.T) {
	t.Run("invalid plan ID format", func(t *testing.T) {
		_, err := getPlan("invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})
}

// Test getCollection function (unit tests)
func TestGetCollection_Unit(t *testing.T) {
	t.Run("invalid collection ID format", func(t *testing.T) {
		_, err := getCollection("invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})
}

// Test projectsGetHandler (unit tests)
func TestSetagayaAPI_ProjectsGetHandler_Unit(t *testing.T) {
	api := &SetagayaAPI{}

	t.Run("missing account in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/projects", nil)
		recorder := httptest.NewRecorder()

		api.projectsGetHandler(recorder, req, nil)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
	})
}

// Test projectGetHandler (unit tests)
func TestSetagayaAPI_ProjectGetHandler_Unit(t *testing.T) {
	api := &SetagayaAPI{}

	t.Run("invalid project ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/projects/invalid", nil)
		recorder := httptest.NewRecorder()
		params := httprouter.Params{{Key: "project_id", Value: "invalid"}}

		api.projectGetHandler(recorder, req, params)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
	})
}

// Test usageSummaryHandler (unit tests)
func TestSetagayaAPI_UsageSummaryHandler_Unit(t *testing.T) {
	// Skip this test as it requires database initialization
	t.Skip("usageSummaryHandler requires database context")
}

func TestSetagayaAPI_handleErrors(t *testing.T) {
	api := &SetagayaAPI{}

	testCases := []struct {
		name           string
		inputError     error
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "no permission error",
			inputError:     makeNoPermissionErr("access denied"),
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "403-access denied",
		},
		{
			name:           "invalid request error",
			inputError:     makeInvalidRequestError("bad data"),
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "400-bad data",
		},
		{
			name:           "login error",
			inputError:     makeLoginError(),
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "403-you need to login",
		},
		{
			name:           "project ownership error",
			inputError:     makeProjectOwnershipError(),
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "403-You don't own the project",
		},
		{
			name:           "collection ownership error",
			inputError:     makeCollectionOwnershipError(),
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "403-You don't own the collection",
		},
		{
			name:           "invalid resource error",
			inputError:     makeInvalidResourceError("project"),
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "400-invalid project",
		},
		{
			name:           "internal server error",
			inputError:     makeInternalServerError("database failed"),
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "500-database failed",
		},
		{
			name:           "unknown error - defaults to internal server error",
			inputError:     errors.New("some unexpected error"),
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "some unexpected error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			api.handleErrors(w, tc.inputError)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var response JSONMessage
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedMsg, response.Message)
		})
	}
}

func TestSetagayaAPI_handleErrors_WithDBError(t *testing.T) {
	api := &SetagayaAPI{}

	// Test that DBError is handled by handleErrorsFromExt
	dbError := &model.DBError{
		Err:     errors.New("connection failed"),
		Message: "Database is unavailable",
	}

	w := httptest.NewRecorder()
	api.handleErrors(w, dbError)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response JSONMessage
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Database is unavailable", response.Message)
}

func TestSetagayaAPI_handleErrors_WithSchedulerError(t *testing.T) {
	api := &SetagayaAPI{}

	// Test that scheduler errors are handled by handleErrorsFromExt
	schedulerError := &scheduler.NoResourcesFoundErr{
		Err:     errors.New("no nodes available"),
		Message: "No compute resources available",
	}

	w := httptest.NewRecorder()
	api.handleErrors(w, schedulerError)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response JSONMessage
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "No compute resources available", response.Message)
}
