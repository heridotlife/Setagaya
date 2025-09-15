package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeFolder(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name       string
		folderPath string
		setup      func(string)
		validate   func(*testing.T, string)
	}{
		{
			name:       "create new folder",
			folderPath: filepath.Join(tempDir, "new-folder"),
			setup:      func(path string) {}, // No setup needed
			validate: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				assert.True(t, info.IsDir())
			},
		},
		{
			name:       "create nested folders",
			folderPath: filepath.Join(tempDir, "parent", "child", "grandchild"),
			setup:      func(path string) {}, // No setup needed
			validate: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				assert.True(t, info.IsDir())

				// Verify parent directories also exist
				parentPath := filepath.Dir(path)
				parentInfo, err := os.Stat(parentPath)
				assert.NoError(t, err)
				assert.True(t, parentInfo.IsDir())
			},
		},
		{
			name:       "folder already exists",
			folderPath: filepath.Join(tempDir, "existing-folder"),
			setup: func(path string) {
				err := os.MkdirAll(path, os.ModePerm)
				assert.NoError(t, err)
			},
			validate: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				assert.True(t, info.IsDir())
			},
		},
		{
			name:       "folder with special characters",
			folderPath: filepath.Join(tempDir, "folder-with_special.chars"),
			setup:      func(path string) {},
			validate: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				assert.True(t, info.IsDir())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(tc.folderPath)

			// This should not panic or error
			MakeFolder(tc.folderPath)

			tc.validate(t, tc.folderPath)
		})
	}
}

func TestMakeFolderPermissions(t *testing.T) {
	tempDir := t.TempDir()
	folderPath := filepath.Join(tempDir, "permission-test")

	MakeFolder(folderPath)

	// Check that the folder was created with correct permissions
	info, err := os.Stat(folderPath)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())

	// On Unix systems, check that permissions include read/write/execute for owner
	mode := info.Mode()
	assert.True(t, mode.IsDir())
	// The exact permissions might vary by system, but directory should be accessible
	assert.True(t, mode&0700 != 0, "Directory should have owner read/write/execute permissions")
}

func TestDeleteFolder(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name     string
		setup    func() string
		validate func(*testing.T, string)
	}{
		{
			name: "delete simple folder",
			setup: func() string {
				folderPath := filepath.Join(tempDir, "simple-folder")
				err := os.MkdirAll(folderPath, os.ModePerm)
				assert.NoError(t, err)
				return folderPath
			},
			validate: func(t *testing.T, path string) {
				_, err := os.Stat(path)
				assert.True(t, os.IsNotExist(err))
			},
		},
		{
			name: "delete folder with files",
			setup: func() string {
				folderPath := filepath.Join(tempDir, "folder-with-files")
				err := os.MkdirAll(folderPath, os.ModePerm)
				assert.NoError(t, err)

				// Create some files
				file1 := filepath.Join(folderPath, "file1.txt")
				err = os.WriteFile(file1, []byte("content1"), 0644)
				assert.NoError(t, err)

				file2 := filepath.Join(folderPath, "file2.txt")
				err = os.WriteFile(file2, []byte("content2"), 0644)
				assert.NoError(t, err)

				return folderPath
			},
			validate: func(t *testing.T, path string) {
				_, err := os.Stat(path)
				assert.True(t, os.IsNotExist(err))
			},
		},
		{
			name: "delete nested folders",
			setup: func() string {
				folderPath := filepath.Join(tempDir, "nested", "deep", "folder")
				err := os.MkdirAll(folderPath, os.ModePerm)
				assert.NoError(t, err)

				// Create a file in the nested folder
				file := filepath.Join(folderPath, "nested-file.txt")
				err = os.WriteFile(file, []byte("nested content"), 0644)
				assert.NoError(t, err)

				// Return the top-level folder to delete
				return filepath.Join(tempDir, "nested")
			},
			validate: func(t *testing.T, path string) {
				_, err := os.Stat(path)
				assert.True(t, os.IsNotExist(err))
			},
		},
		{
			name: "delete non-existent folder",
			setup: func() string {
				return filepath.Join(tempDir, "non-existent-folder")
			},
			validate: func(t *testing.T, path string) {
				// Should not panic or error, folder remains non-existent
				_, err := os.Stat(path)
				assert.True(t, os.IsNotExist(err))
			},
		},
		{
			name: "delete folder with subdirectories",
			setup: func() string {
				basePath := filepath.Join(tempDir, "complex-folder")

				// Create multiple subdirectories
				dirs := []string{
					filepath.Join(basePath, "subdir1"),
					filepath.Join(basePath, "subdir2", "subsubdir"),
					filepath.Join(basePath, "subdir3"),
				}

				for _, dir := range dirs {
					err := os.MkdirAll(dir, os.ModePerm)
					assert.NoError(t, err)

					// Add a file to each directory
					file := filepath.Join(dir, "test.txt")
					err = os.WriteFile(file, []byte("test content"), 0644)
					assert.NoError(t, err)
				}

				return basePath
			},
			validate: func(t *testing.T, path string) {
				_, err := os.Stat(path)
				assert.True(t, os.IsNotExist(err))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			folderPath := tc.setup()

			// This should not panic or error
			DeleteFolder(folderPath)

			tc.validate(t, folderPath)
		})
	}
}

func TestMakeAndDeleteFolderIntegration(t *testing.T) {
	tempDir := t.TempDir()
	folderPath := filepath.Join(tempDir, "integration-test")

	// Create folder
	MakeFolder(folderPath)

	// Verify it exists
	info, err := os.Stat(folderPath)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())

	// Add some content
	subfolderPath := filepath.Join(folderPath, "subfolder")
	MakeFolder(subfolderPath)

	filePath := filepath.Join(subfolderPath, "test.txt")
	err = os.WriteFile(filePath, []byte("test content"), 0644)
	assert.NoError(t, err)

	// Verify content exists
	_, err = os.Stat(filePath)
	assert.NoError(t, err)

	// Delete the entire folder
	DeleteFolder(folderPath)

	// Verify it's gone
	_, err = os.Stat(folderPath)
	assert.True(t, os.IsNotExist(err))

	// Verify subfolder and file are also gone
	_, err = os.Stat(subfolderPath)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err))
}

func TestMakeFolderIdempotent(t *testing.T) {
	tempDir := t.TempDir()
	folderPath := filepath.Join(tempDir, "idempotent-test")

	// Create folder multiple times
	MakeFolder(folderPath)
	MakeFolder(folderPath)
	MakeFolder(folderPath)

	// Should still exist and be a directory
	info, err := os.Stat(folderPath)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestDeleteFolderIdempotent(t *testing.T) {
	tempDir := t.TempDir()
	folderPath := filepath.Join(tempDir, "delete-idempotent-test")

	// Create and delete folder
	MakeFolder(folderPath)
	DeleteFolder(folderPath)

	// Delete again (should not panic)
	DeleteFolder(folderPath)
	DeleteFolder(folderPath)

	// Should remain non-existent
	_, err := os.Stat(folderPath)
	assert.True(t, os.IsNotExist(err))
}

func TestFolderEdgeCases(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		// Test with empty string - should not panic
		MakeFolder("")
		DeleteFolder("")
	})

	t.Run("root path", func(t *testing.T) {
		// Test with root path - should not panic but likely won't work
		// This test mainly ensures no panic occurs
		MakeFolder("/")
		// Don't delete root!
	})

	t.Run("relative path", func(t *testing.T) {
		// Test with relative path
		tempDir := t.TempDir()
		oldWd, err := os.Getwd()
		assert.NoError(t, err)

		err = os.Chdir(tempDir)
		assert.NoError(t, err)
		defer func() {
			if chdirErr := os.Chdir(oldWd); chdirErr != nil {
				t.Logf("Failed to change directory back: %v", chdirErr)
			}
		}()

		relativePath := "relative-folder"
		MakeFolder(relativePath)

		info, err := os.Stat(relativePath)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())

		DeleteFolder(relativePath)

		_, err = os.Stat(relativePath)
		assert.True(t, os.IsNotExist(err))
	})
}
