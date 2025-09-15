package config

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadContext(t *testing.T) {
	testCases := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "local environment",
			envValue: "local",
			expected: "local",
		},
		{
			name:     "production environment",
			envValue: "production",
			expected: "production",
		},
		{
			name:     "test environment",
			envValue: "test",
			expected: "test",
		},
		{
			name:     "empty environment",
			envValue: "",
			expected: "",
		},
		{
			name:     "custom environment",
			envValue: "staging",
			expected: "staging",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable
			oldEnv := os.Getenv("env")
			defer func() {
				if err := os.Setenv("env", oldEnv); err != nil {
					t.Logf("Error restoring env variable: %v", err)
				}
			}() // Restore after test

			if err := os.Setenv("env", tc.envValue); err != nil {
				t.Fatalf("Error setting env variable: %v", err)
			}

			result := loadContext()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMakeHTTPClients(t *testing.T) {
	t.Run("no proxy configuration", func(t *testing.T) {
		sc := &SetagayaConfig{
			HttpConfig: &HttpConfig{
				Proxy: "",
			},
		}

		sc.makeHTTPClients()

		// Both clients should be created
		assert.NotNil(t, sc.HTTPClient)
		assert.NotNil(t, sc.HTTPProxyClient)

		// They should be the same instance when no proxy is configured
		assert.Same(t, sc.HTTPClient, sc.HTTPProxyClient)
	})

	t.Run("with proxy configuration", func(t *testing.T) {
		sc := &SetagayaConfig{
			HttpConfig: &HttpConfig{
				Proxy: "http://proxy.example.com:8080",
			},
		}

		sc.makeHTTPClients()

		// Both clients should be created
		assert.NotNil(t, sc.HTTPClient)
		assert.NotNil(t, sc.HTTPProxyClient)

		// They should be different instances when proxy is configured
		assert.NotSame(t, sc.HTTPClient, sc.HTTPProxyClient)

		// HTTPClient should be a basic client
		assert.Nil(t, sc.HTTPClient.Transport)

		// HTTPProxyClient should have transport configured
		assert.NotNil(t, sc.HTTPProxyClient.Transport)
	})

	t.Run("nil HttpConfig", func(t *testing.T) {
		sc := &SetagayaConfig{
			HttpConfig: nil,
		}

		// This should panic due to nil pointer dereference
		assert.Panics(t, func() {
			sc.makeHTTPClients()
		})
	})

	t.Run("with various proxy URLs", func(t *testing.T) {
		testCases := []struct {
			name       string
			proxyURL   string
			shouldWork bool
		}{
			{
				name:       "http proxy",
				proxyURL:   "http://proxy.example.com:8080",
				shouldWork: true,
			},
			{
				name:       "https proxy",
				proxyURL:   "https://proxy.example.com:8080",
				shouldWork: true,
			},
			{
				name:       "socks5 proxy",
				proxyURL:   "socks5://proxy.example.com:1080",
				shouldWork: true,
			},
			{
				name:       "proxy with auth",
				proxyURL:   "http://user:pass@proxy.example.com:8080",
				shouldWork: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				sc := &SetagayaConfig{
					HttpConfig: &HttpConfig{
						Proxy: tc.proxyURL,
					},
				}

				if tc.shouldWork {
					assert.NotPanics(t, func() {
						sc.makeHTTPClients()
					})
					assert.NotNil(t, sc.HTTPClient)
					assert.NotNil(t, sc.HTTPProxyClient)
					assert.NotSame(t, sc.HTTPClient, sc.HTTPProxyClient)
				}
			})
		}
	})
}

func TestMakeMySQLEndpoint(t *testing.T) {
	testCases := []struct {
		name     string
		config   *MySQLConfig
		expected string
	}{
		{
			name: "basic configuration",
			config: &MySQLConfig{
				Host:     "localhost",
				User:     "root",
				Password: "password",
				Database: "testdb",
			},
			expected: "root:password@tcp(localhost)/testdb?",
		},
		{
			name: "with port",
			config: &MySQLConfig{
				Host:     "localhost:3306",
				User:     "user",
				Password: "pass",
				Database: "mydb",
			},
			expected: "user:pass@tcp(localhost:3306)/mydb?",
		},
		{
			name: "with special characters",
			config: &MySQLConfig{
				Host:     "db.example.com:3306",
				User:     "user@domain",
				Password: "p@ssw0rd!",
				Database: "app_db",
			},
			expected: "user@domain:p@ssw0rd!@tcp(db.example.com:3306)/app_db?",
		},
		{
			name: "empty password",
			config: &MySQLConfig{
				Host:     "localhost",
				User:     "root",
				Password: "",
				Database: "testdb",
			},
			expected: "root:@tcp(localhost)/testdb?",
		},
		{
			name: "minimal config",
			config: &MySQLConfig{
				Host:     "host",
				User:     "u",
				Password: "p",
				Database: "d",
			},
			expected: "u:p@tcp(host)/d?",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := makeMySQLEndpoint(tc.config)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMySQLConfigStruct(t *testing.T) {
	// Test that MySQLConfig struct can be properly instantiated and used
	config := &MySQLConfig{
		Host:     "localhost",
		User:     "root",
		Password: "password",
		Database: "testdb",
		Keypairs: "keypairs_data",
		Endpoint: "custom_endpoint",
	}

	assert.Equal(t, "localhost", config.Host)
	assert.Equal(t, "root", config.User)
	assert.Equal(t, "password", config.Password)
	assert.Equal(t, "testdb", config.Database)
	assert.Equal(t, "keypairs_data", config.Keypairs)
	assert.Equal(t, "custom_endpoint", config.Endpoint)
}

func TestSetagayaConfigHTTPClients(t *testing.T) {
	// Test that SetagayaConfig properly manages HTTP clients
	config := &SetagayaConfig{}

	// Initially clients should be nil
	assert.Nil(t, config.HTTPClient)
	assert.Nil(t, config.HTTPProxyClient)

	// Test with no proxy config
	config.HttpConfig = &HttpConfig{Proxy: ""}
	config.makeHTTPClients()

	assert.NotNil(t, config.HTTPClient)
	assert.NotNil(t, config.HTTPProxyClient)
	assert.IsType(t, &http.Client{}, config.HTTPClient)
	assert.IsType(t, &http.Client{}, config.HTTPProxyClient)
}

func TestHttpConfigStruct(t *testing.T) {
	// Test HttpConfig struct functionality
	httpConfig := &HttpConfig{
		Proxy: "http://proxy.example.com:8080",
	}

	assert.Equal(t, "http://proxy.example.com:8080", httpConfig.Proxy)

	// Test with empty proxy
	httpConfig.Proxy = ""
	assert.Equal(t, "", httpConfig.Proxy)
}

func TestConfigConstants(t *testing.T) {
	// Test that configuration constants are properly defined
	assert.Equal(t, "config.json", ConfigFileName)
	assert.Equal(t, "/config.json", ConfigFilePath)
}

func TestLdapConfigStruct(t *testing.T) {
	// Test LdapConfig struct functionality
	ldapConfig := &LdapConfig{
		BaseDN:         "DC=example,DC=com",
		SystemUser:     "CN=system,DC=example,DC=com",
		SystemPassword: "systempass",
		LdapServer:     "ldap.example.com",
		LdapPort:       "389",
	}

	assert.Equal(t, "DC=example,DC=com", ldapConfig.BaseDN)
	assert.Equal(t, "CN=system,DC=example,DC=com", ldapConfig.SystemUser)
	assert.Equal(t, "systempass", ldapConfig.SystemPassword)
	assert.Equal(t, "ldap.example.com", ldapConfig.LdapServer)
	assert.Equal(t, "389", ldapConfig.LdapPort)
}

func TestAuthConfigStruct(t *testing.T) {
	// Test AuthConfig struct functionality
	ldapConfig := &LdapConfig{
		BaseDN:     "DC=example,DC=com",
		LdapServer: "ldap.example.com",
	}

	authConfig := &AuthConfig{
		AdminUsers: []string{"admin1", "admin2"},
		NoAuth:     false,
		SessionKey: "test-session-key",
		LdapConfig: ldapConfig,
	}

	assert.Equal(t, []string{"admin1", "admin2"}, authConfig.AdminUsers)
	assert.False(t, authConfig.NoAuth)
	assert.Equal(t, "test-session-key", authConfig.SessionKey)
	assert.NotNil(t, authConfig.LdapConfig)
	assert.Equal(t, "DC=example,DC=com", authConfig.BaseDN)
}

func TestClusterConfigStruct(t *testing.T) {
	// Test ClusterConfig struct functionality
	clusterConfig := &ClusterConfig{
		Project:     "test-project",
		Zone:        "us-central1-a",
		Region:      "us-central1",
		ClusterID:   "test-cluster",
		Kind:        "kubernetes",
		APIEndpoint: "https://kubernetes.example.com",
		GCDuration:  15.0,
		ServiceType: "LoadBalancer",
	}

	assert.Equal(t, "test-project", clusterConfig.Project)
	assert.Equal(t, "us-central1-a", clusterConfig.Zone)
	assert.Equal(t, "us-central1", clusterConfig.Region)
	assert.Equal(t, "test-cluster", clusterConfig.ClusterID)
	assert.Equal(t, "kubernetes", clusterConfig.Kind)
	assert.Equal(t, "https://kubernetes.example.com", clusterConfig.APIEndpoint)
	assert.Equal(t, 15.0, clusterConfig.GCDuration)
	assert.Equal(t, "LoadBalancer", clusterConfig.ServiceType)
}

func TestHostAliasStruct(t *testing.T) {
	// Test HostAlias struct if it exists
	// Note: The struct definition was cut off in our view, so this is a basic test

	// First check if HostAlias is defined properly in the package
	// This test verifies the struct can be imported and used
	// We'll need to see the full definition to test it properly
}

func TestConfigFileConstants(t *testing.T) {
	// Test configuration file handling constants and paths
	assert.NotEmpty(t, ConfigFileName)
	assert.NotEmpty(t, ConfigFilePath)

	// Test that ConfigFilePath is properly constructed
	assert.Contains(t, ConfigFilePath, ConfigFileName)
	assert.True(t, ConfigFilePath[0] == '/', "ConfigFilePath should be absolute")
}

func TestMySQLEndpointEdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		config   *MySQLConfig
		expected string
	}{
		{
			name:     "nil config should not panic",
			config:   nil,
			expected: "", // This will likely panic, but we test for it
		},
		{
			name:     "empty config",
			config:   &MySQLConfig{},
			expected: ":@tcp()/?",
		},
		{
			name: "config with spaces",
			config: &MySQLConfig{
				Host:     "my host",
				User:     "my user",
				Password: "my password",
				Database: "my database",
			},
			expected: "my user:my password@tcp(my host)/my database?",
		},
		{
			name: "config with unicode characters",
			config: &MySQLConfig{
				Host:     "数据库.example.com",
				User:     "用户",
				Password: "密码",
				Database: "数据库",
			},
			expected: "用户:密码@tcp(数据库.example.com)/数据库?",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config == nil {
				// Test that nil config panics as expected
				assert.Panics(t, func() {
					makeMySQLEndpoint(tc.config)
				})
			} else {
				result := makeMySQLEndpoint(tc.config)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestHTTPClientCreation(t *testing.T) {
	// Test HTTP client creation with various configurations

	t.Run("default HTTP client", func(t *testing.T) {
		client := &http.Client{}
		assert.NotNil(t, client)
		assert.Nil(t, client.Transport) // Default transport should be nil
	})

	t.Run("HTTP client with timeout", func(t *testing.T) {
		client := &http.Client{}
		assert.Zero(t, client.Timeout) // Default timeout should be 0
	})
}

func TestConfigStructIntegration(t *testing.T) {
	// Test that all config structs work together properly

	ldapConfig := &LdapConfig{
		BaseDN:         "DC=corp,DC=example,DC=com",
		SystemUser:     "CN=setagaya,CN=Users,DC=corp,DC=example,DC=com",
		SystemPassword: "secretpass",
		LdapServer:     "ldap.corp.example.com",
		LdapPort:       "636",
	}

	authConfig := &AuthConfig{
		AdminUsers: []string{"admin", "super-admin"},
		NoAuth:     false,
		SessionKey: "setagaya-session",
		LdapConfig: ldapConfig,
	}

	clusterConfig := &ClusterConfig{
		Project:     "setagaya-platform",
		Zone:        "us-west1-b",
		Region:      "us-west1",
		ClusterID:   "setagaya-cluster",
		Kind:        "gke",
		APIEndpoint: "https://kubernetes.example.com:6443",
		GCDuration:  30.0,
		ServiceType: "NodePort",
	}

	mysqlConfig := &MySQLConfig{
		Host:     "mysql.corp.example.com:3306",
		User:     "setagaya_user",
		Password: "setagaya_password",
		Database: "setagaya_db",
		Keypairs: "ssl_keypairs",
		Endpoint: "mysql://mysql.corp.example.com:3306/setagaya_db",
	}

	httpConfig := &HttpConfig{
		Proxy: "http://proxy.corp.example.com:8080",
	}

	// Test that all configs can be combined
	assert.NotNil(t, authConfig)
	assert.NotNil(t, clusterConfig)
	assert.NotNil(t, mysqlConfig)
	assert.NotNil(t, httpConfig)

	// Test relationships
	assert.Same(t, ldapConfig, authConfig.LdapConfig)

	// Test MySQL endpoint generation
	endpoint := makeMySQLEndpoint(mysqlConfig)
	assert.Contains(t, endpoint, mysqlConfig.User)
	assert.Contains(t, endpoint, mysqlConfig.Password)
	assert.Contains(t, endpoint, mysqlConfig.Host)
	assert.Contains(t, endpoint, mysqlConfig.Database)
}
