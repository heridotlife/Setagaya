package model

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"

	"github.com/hveda/Setagaya/setagaya/config"
)

func setupTestConfig() error {
	// Create a test config that doesn't require external dependencies
	testConfig := &config.SetagayaConfig{
		ProjectHome:     "test-project-home",
		UploadFileHelp:  "test-upload-help",
		DistributedMode: false,
		DevMode:         true,
		Context:         "test",
		DBConf: &config.MySQLConfig{
			Host:     "localhost",
			User:     "test",
			Password: "test",
			Database: "setagaya_test",
		},
		AuthConfig: &config.AuthConfig{
			AdminUsers: []string{"test-admin"},
			NoAuth:     true,
			SessionKey: "test-session-key",
			LdapConfig: &config.LdapConfig{
				BaseDN:         "dc=test,dc=local",
				SystemUser:     "test",
				SystemPassword: "test",
				LdapServer:     "localhost",
				LdapPort:       "389",
			},
		},
		ObjectStorage: &config.ObjectStorage{
			Provider: "local",
			Url:      "http://localhost:8080",
			Bucket:   "setagaya-test",
		},
		LogFormat: &config.LogFormat{
			Json: false,
		},
	}

	// Mock database connection for testing
	mockDB := &sql.DB{}
	testConfig.DBC = mockDB

	// Set the global config
	config.SC = testConfig
	return nil
}

// executeDelete executes a delete statement and closes the prepared statement
func executeDelete(db *sql.DB, query string) error {
	q, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()

	_, err = q.Exec()
	return err
}

func setupAndTeardown() error {
	// Skip database operations if no real DB connection
	if config.SC.DBC == nil {
		return nil
	}

	db := config.SC.DBC

	// List of tables to clean up in order
	tablesToClean := []string{
		"plan",
		"running_plan",
		"collection",
		"collection_plan",
		"project",
		"collection_run",
		"collection_run_history",
	}

	// Execute delete statements for each table
	for _, table := range tablesToClean {
		if err := executeDelete(db, "delete from "+table); err != nil {
			return err
		}
	}

	return nil
}

// SetupTestEnvironment initializes a test environment with mock config
func SetupTestEnvironment(t *testing.T) func() {
	// Store original config
	originalConfig := config.SC

	// Setup test config
	if err := setupTestConfig(); err != nil {
		t.Fatalf("Failed to setup test config: %v", err)
	}

	// Return cleanup function
	return func() {
		config.SC = originalConfig
	}
}

// CreateTestConfigFile creates a temporary config file for testing
func CreateTestConfigFile(t *testing.T) (string, func()) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	testConfig := map[string]interface{}{
		"bg_color":         "#fff",
		"project_home":     "test-project-home",
		"upload_file_help": "test-upload-help",
		"auth_config": map[string]interface{}{
			"admin_users":     []string{},
			"ldap_server":     "localhost",
			"ldap_port":       "389",
			"system_user":     "test",
			"system_password": "test",
			"base_dn":         "dc=test,dc=local",
			"no_auth":         true,
			"session_key":     "test-session-key",
		},
		"http_config": map[string]interface{}{
			"proxy": "",
		},
		"db": map[string]interface{}{
			"host":     "localhost",
			"user":     "test",
			"password": "test",
			"database": "setagaya_test",
		},
		"executors": map[string]interface{}{
			"cluster": map[string]interface{}{
				"on_demand":   false,
				"kind":        "k8s",
				"gc_duration": 15,
			},
			"in_cluster": false,
			"namespace":  "setagaya-executors-test",
			"jmeter": map[string]interface{}{
				"image": "setagaya:jmeter-test",
				"cpu":   "0.1",
				"mem":   "512Mi",
			},
			"pull_secret":               "",
			"pull_policy":               "IfNotPresent",
			"max_engines_in_collection": 10,
		},
		"ingress": map[string]interface{}{
			"image":     "setagaya:ingress-controller-test",
			"cpu":       "0.1",
			"lifespan":  "30m",
			"gc_period": "30s",
		},
		"dashboard": map[string]interface{}{
			"url":              "http://localhost:3000",
			"run_dashboard":    "/d/test/setagaya",
			"engine_dashboard": "/d/test/setagaya-engine-health",
		},
		"object_storage": map[string]interface{}{
			"provider": "local",
			"url":      "http://localhost:8080",
			"user":     "",
			"password": "",
			"bucket":   "setagaya-test",
		},
		"log_format": map[string]interface{}{
			"json": false,
		},
	}

	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Override the config file path
	originalPath := config.ConfigFilePath
	config.ConfigFilePath = configPath

	return configPath, func() {
		config.ConfigFilePath = originalPath
		if err := os.Remove(configPath); err != nil {
			log.WithError(err).Warnf("Failed to remove temporary config file: %s", configPath)
		}
	}
}
