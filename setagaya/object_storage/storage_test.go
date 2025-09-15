package object_storage

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileNotFoundError(t *testing.T) {
	// Test FileNotFound error type
	err := FileNotFoundError()

	assert.Error(t, err)
	assert.Equal(t, "File not found", err.Error())

	// Test that it implements error interface
	var errorInterface = err
	assert.Equal(t, "File not found", errorInterface.Error())
}

func TestFileNotFoundStruct(t *testing.T) {
	// Test FileNotFound struct directly
	fnf := FileNotFound{err: "custom error message"}

	assert.Equal(t, "custom error message", fnf.Error())

	// Test empty error message
	emptyFnf := FileNotFound{err: ""}
	assert.Equal(t, "", emptyFnf.Error())
}

func TestFileNotFoundErrorType(t *testing.T) {
	// Test that FileNotFoundError returns correct type
	err := FileNotFoundError()

	// Check if we can type assert to FileNotFound
	fnf, ok := err.(FileNotFound)
	assert.True(t, ok)
	assert.Equal(t, "File not found", fnf.err)
}

// MockStorage implements StorageInterface for testing
type MockStorage struct {
	files         map[string][]byte
	baseURL       string
	uploadError   error
	deleteError   error
	downloadError error
}

func NewMockStorage(baseURL string) *MockStorage {
	return &MockStorage{
		files:   make(map[string][]byte),
		baseURL: baseURL,
	}
}

func (m *MockStorage) Upload(filename string, content io.ReadCloser) error {
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

func (m *MockStorage) Delete(filename string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	if _, exists := m.files[filename]; !exists {
		return FileNotFoundError()
	}

	delete(m.files, filename)
	return nil
}

func (m *MockStorage) GetUrl(filename string) string {
	return m.baseURL + "/" + filename
}

func (m *MockStorage) Download(filename string) ([]byte, error) {
	if m.downloadError != nil {
		return nil, m.downloadError
	}

	data, exists := m.files[filename]
	if !exists {
		return nil, FileNotFoundError()
	}

	return data, nil
}

// SetErrors allows setting errors for testing error conditions
func (m *MockStorage) SetUploadError(err error) {
	m.uploadError = err
}

func (m *MockStorage) SetDeleteError(err error) {
	m.deleteError = err
}

func (m *MockStorage) SetDownloadError(err error) {
	m.downloadError = err
}

func TestMockStorageImplementsInterface(t *testing.T) {
	// Test that MockStorage implements StorageInterface
	var storage StorageInterface = NewMockStorage("http://test.com")
	assert.NotNil(t, storage)
}

func TestMockStorageUpload(t *testing.T) {
	storage := NewMockStorage("http://test.com")
	testData := "test file content"
	filename := "test.txt"

	// Test successful upload
	content := io.NopCloser(strings.NewReader(testData))
	err := storage.Upload(filename, content)

	assert.NoError(t, err)
	assert.Equal(t, []byte(testData), storage.files[filename])
}

func TestMockStorageDownload(t *testing.T) {
	storage := NewMockStorage("http://test.com")
	testData := "test file content"
	filename := "test.txt"

	// Upload first
	content := io.NopCloser(strings.NewReader(testData))
	err := storage.Upload(filename, content)
	assert.NoError(t, err)

	// Test successful download
	downloaded, err := storage.Download(filename)
	assert.NoError(t, err)
	assert.Equal(t, []byte(testData), downloaded)

	// Test download non-existent file
	_, err = storage.Download("nonexistent.txt")
	assert.Error(t, err)
	assert.IsType(t, FileNotFound{}, err)
}

func TestMockStorageDelete(t *testing.T) {
	storage := NewMockStorage("http://test.com")
	testData := "test file content"
	filename := "test.txt"

	// Upload first
	content := io.NopCloser(strings.NewReader(testData))
	err := storage.Upload(filename, content)
	assert.NoError(t, err)

	// Test successful delete
	err = storage.Delete(filename)
	assert.NoError(t, err)
	assert.NotContains(t, storage.files, filename)

	// Test delete non-existent file
	err = storage.Delete("nonexistent.txt")
	assert.Error(t, err)
	assert.IsType(t, FileNotFound{}, err)
}

func TestMockStorageGetUrl(t *testing.T) {
	baseURL := "http://test.com"
	storage := NewMockStorage(baseURL)
	filename := "test.txt"

	url := storage.GetUrl(filename)
	expected := baseURL + "/" + filename
	assert.Equal(t, expected, url)
}

func TestMockStorageErrorConditions(t *testing.T) {
	storage := NewMockStorage("http://test.com")
	testError := assert.AnError

	// Test upload error
	storage.SetUploadError(testError)
	content := io.NopCloser(strings.NewReader("test"))
	err := storage.Upload("test.txt", content)
	assert.Equal(t, testError, err)

	// Reset and test delete error
	storage.SetUploadError(nil)
	storage.SetDeleteError(testError)
	err = storage.Delete("test.txt")
	assert.Equal(t, testError, err)

	// Reset and test download error
	storage.SetDeleteError(nil)
	storage.SetDownloadError(testError)
	_, err = storage.Download("test.txt")
	assert.Equal(t, testError, err)
}

func TestStorageInterfaceUsage(t *testing.T) {
	// Test that we can use MockStorage through the interface
	var storage StorageInterface = NewMockStorage("http://test.com")

	testData := "interface test content"
	filename := "interface_test.txt"

	// Upload through interface
	content := io.NopCloser(strings.NewReader(testData))
	err := storage.Upload(filename, content)
	assert.NoError(t, err)

	// Download through interface
	downloaded, err := storage.Download(filename)
	assert.NoError(t, err)
	assert.Equal(t, []byte(testData), downloaded)

	// Get URL through interface
	url := storage.GetUrl(filename)
	assert.Equal(t, "http://test.com/interface_test.txt", url)

	// Delete through interface
	err = storage.Delete(filename)
	assert.NoError(t, err)

	// Verify file is gone
	_, err = storage.Download(filename)
	assert.Error(t, err)
}
