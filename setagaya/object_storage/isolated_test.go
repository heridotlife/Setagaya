package object_storage

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test the core storage interface and error types without dependencies

func TestFileNotFoundError_Isolated(t *testing.T) {
	// Test FileNotFound error type
	err := FileNotFoundError()

	assert.Error(t, err)
	assert.Equal(t, "File not found", err.Error())

	// Test that it implements error interface
	var errorInterface = err
	assert.Equal(t, "File not found", errorInterface.Error())
}

func TestFileNotFoundStruct_Isolated(t *testing.T) {
	// Test FileNotFound struct directly
	fnf := FileNotFound{err: "custom error message"}

	assert.Equal(t, "custom error message", fnf.Error())

	// Test empty error message
	emptyFnf := FileNotFound{err: ""}
	assert.Equal(t, "", emptyFnf.Error())
}

func TestStorageInterfaceContract(t *testing.T) {
	// Test that our interface is well-defined
	// This is a compile-time test - if the interface changes, this will fail to compile

	var storage StorageInterface

	// These should compile but will panic at runtime since storage is nil
	// We're just testing the interface contract
	assert.Panics(t, func() {
		_ = storage.Upload("test", nil)
	})

	assert.Panics(t, func() {
		_ = storage.Delete("test")
	})

	assert.Panics(t, func() {
		_, _ = storage.Download("test")
	})

	assert.Panics(t, func() {
		storage.GetUrl("test")
	})
}

// MockStorage for isolated testing
type TestMockStorage struct {
	files         map[string][]byte
	baseURL       string
	uploadError   error
	deleteError   error
	downloadError error
}

func NewTestMockStorage(baseURL string) *TestMockStorage {
	return &TestMockStorage{
		files:   make(map[string][]byte),
		baseURL: baseURL,
	}
}

func (m *TestMockStorage) Upload(filename string, content io.ReadCloser) error {
	if m.uploadError != nil {
		return m.uploadError
	}

	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	if closeErr := content.Close(); closeErr != nil {
		return closeErr
	}

	m.files[filename] = data
	return nil
}

func (m *TestMockStorage) Delete(filename string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	if _, exists := m.files[filename]; !exists {
		return FileNotFoundError()
	}

	delete(m.files, filename)
	return nil
}

func (m *TestMockStorage) GetUrl(filename string) string {
	return m.baseURL + "/" + filename
}

func (m *TestMockStorage) Download(filename string) ([]byte, error) {
	if m.downloadError != nil {
		return nil, m.downloadError
	}

	data, exists := m.files[filename]
	if !exists {
		return nil, FileNotFoundError()
	}

	return data, nil
}

func (m *TestMockStorage) SetUploadError(err error) {
	m.uploadError = err
}

func (m *TestMockStorage) SetDeleteError(err error) {
	m.deleteError = err
}

func (m *TestMockStorage) SetDownloadError(err error) {
	m.downloadError = err
}

func TestMockStorageBasicOperations(t *testing.T) {
	storage := NewTestMockStorage("http://test.example.com")
	testData := "test file content for mock storage"
	filename := "test-file.txt"

	// Test URL generation
	expectedURL := "http://test.example.com/test-file.txt"
	actualURL := storage.GetUrl(filename)
	assert.Equal(t, expectedURL, actualURL)

	// Test upload
	content := io.NopCloser(strings.NewReader(testData))
	err := storage.Upload(filename, content)
	assert.NoError(t, err)
	assert.Equal(t, []byte(testData), storage.files[filename])

	// Test download
	downloaded, err := storage.Download(filename)
	assert.NoError(t, err)
	assert.Equal(t, []byte(testData), downloaded)

	// Test delete
	err = storage.Delete(filename)
	assert.NoError(t, err)
	assert.NotContains(t, storage.files, filename)

	// Test download after delete
	_, err = storage.Download(filename)
	assert.Error(t, err)
	assert.IsType(t, FileNotFound{}, err)
}

func TestMockStorageErrorHandling(t *testing.T) {
	storage := NewTestMockStorage("http://test.example.com")
	testError := assert.AnError

	// Test upload error
	storage.SetUploadError(testError)
	content := io.NopCloser(strings.NewReader("test"))
	err := storage.Upload("test.txt", content)
	assert.Equal(t, testError, err)

	// Test download error
	storage.SetUploadError(nil)
	storage.SetDownloadError(testError)
	_, err = storage.Download("test.txt")
	assert.Equal(t, testError, err)

	// Test delete error
	storage.SetDownloadError(nil)
	storage.SetDeleteError(testError)
	err = storage.Delete("test.txt")
	assert.Equal(t, testError, err)
}

func TestMockStorageInterfaceCompliance(t *testing.T) {
	// Verify MockStorage implements StorageInterface
	var storage StorageInterface = NewTestMockStorage("http://test.example.com")
	assert.NotNil(t, storage)

	// Test through interface
	testData := "interface compliance test"
	filename := "interface-test.txt"

	content := io.NopCloser(strings.NewReader(testData))
	err := storage.Upload(filename, content)
	assert.NoError(t, err)

	url := storage.GetUrl(filename)
	assert.Equal(t, "http://test.example.com/interface-test.txt", url)

	downloaded, err := storage.Download(filename)
	assert.NoError(t, err)
	assert.Equal(t, []byte(testData), downloaded)

	err = storage.Delete(filename)
	assert.NoError(t, err)
}

func TestStorageProviderConstants_Isolated(t *testing.T) {
	// Test constants without triggering config initialization
	assert.Equal(t, "nexus", nexusStorageProvider)
	assert.Equal(t, "gcp", gcpStorageProvider)
	assert.Equal(t, "local", localStorageProvider)

	// Test the slice
	expected := []string{"nexus", "gcp", "local"}
	assert.Equal(t, expected, allStorageProvidder)
}
