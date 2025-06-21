package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/david22573/envspace/vault"
)

// StorageBackend defines the interface for vault storage
type StorageBackend interface {
	Save(manager *vault.VaultManager) error
	Load() (*vault.VaultManager, error)
	Backup() error
	Exists() bool
	Delete() error
}

// FileStorageConfig contains configuration for file-based storage
type FileStorageConfig struct {
	FilePath    string
	BackupDir   string
	MaxBackups  int
	Permissions os.FileMode
	AutoBackup  bool
}

// FileStorage implements file-based storage for vault managers
type FileStorage struct {
	config FileStorageConfig
	mutex  sync.Mutex
}

// StorageMetadata is written to the file header for validation
type StorageMetadata struct {
	Version     int       `json:"version"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Checksum    string    `json:"checksum"`
	Application string    `json:"application"`
}

// StorageContainer wraps the manager with metadata
type StorageContainer struct {
	Metadata StorageMetadata     `json:"metadata"`
	Manager  *vault.VaultManager `json:"manager"`
}

// NewFileStorage creates a new file storage backend
func NewFileStorage(config FileStorageConfig) *FileStorage {
	// Set defaults
	if config.Permissions == 0 {
		config.Permissions = 0600 // Read/write for owner only
	}
	if config.MaxBackups == 0 {
		config.MaxBackups = 5
	}
	if config.BackupDir == "" {
		config.BackupDir = filepath.Dir(config.FilePath) + "/backups"
	}

	return &FileStorage{
		config: config,
	}
}

// Save writes the vault manager to file with atomic operation
func (fs *FileStorage) Save(manager *vault.VaultManager) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// Ensure manager saves its vault data first
	if err := manager.Save(); err != nil {
		return fmt.Errorf("failed to prepare manager for save: %w", err)
	}

	// Create backup if file exists and auto-backup is enabled
	if fs.config.AutoBackup && fs.Exists() {
		if err := fs.createBackup(); err != nil {
			// Log warning but don't fail the save
			fmt.Printf("Warning: failed to create backup: %v\n", err)
		}
	}

	// Serialize manager
	managerData, err := json.Marshal(manager)
	if err != nil {
		return fmt.Errorf("failed to serialize manager: %w", err)
	}

	// Compute checksum
	checksum := sha256.Sum256(managerData)
	checksumHex := hex.EncodeToString(checksum[:])

	// Create storage container
	container := StorageContainer{
		Metadata: StorageMetadata{
			Version:     1,
			Created:     time.Now(),
			Modified:    time.Now(),
			Checksum:    checksumHex,
			Application: "vault-manager-v1",
		},
		Manager: manager,
	}

	// Serialize complete container
	data, err := json.Marshal(container)
	if err != nil {
		return fmt.Errorf("failed to serialize container: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tempFile := fs.config.FilePath + ".tmp"
	if err := fs.writeFile(tempFile, data); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, fs.config.FilePath); err != nil {
		os.Remove(tempFile) // Cleanup temp file
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// Load reads and validates the vault manager from file
func (fs *FileStorage) Load() (*vault.VaultManager, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if !fs.Exists() {
		return nil, fmt.Errorf("vault file does not exist: %s", fs.config.FilePath)
	}

	// Read file
	data, err := os.ReadFile(fs.config.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	// Parse container
	var container StorageContainer
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to parse vault file: %w", err)
	}

	// Validate metadata
	if err := fs.validateMetadata(container.Metadata, container.Manager); err != nil {
		return nil, fmt.Errorf("file validation failed: %w", err)
	}

	return container.Manager, nil
}

// Backup creates a timestamped backup of the current vault file
func (fs *FileStorage) Backup() error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if !fs.Exists() {
		return fmt.Errorf("no vault file to backup")
	}

	return fs.createBackup()
}

// Exists checks if the vault file exists
func (fs *FileStorage) Exists() bool {
	_, err := os.Stat(fs.config.FilePath)
	return err == nil
}

// Delete removes the vault file (use with caution!)
func (fs *FileStorage) Delete() error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if !fs.Exists() {
		return nil // Already deleted
	}

	return os.Remove(fs.config.FilePath)
}

// createBackup creates a timestamped backup file
func (fs *FileStorage) createBackup() error {
	// Ensure backup directory exists
	if err := os.MkdirAll(fs.config.BackupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("vault-backup-%s.json", timestamp)
	backupPath := filepath.Join(fs.config.BackupDir, backupName)

	// Copy current file to backup
	if err := fs.copyFile(fs.config.FilePath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Clean up old backups
	if err := fs.cleanupOldBackups(); err != nil {
		// Log warning but don't fail
		fmt.Printf("Warning: failed to cleanup old backups: %v\n", err)
	}

	return nil
}

// copyFile copies a file from src to dst
func (fs *FileStorage) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fs.config.Permissions)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// writeFile writes data to file with proper permissions
func (fs *FileStorage) writeFile(path string, data []byte) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(path, data, fs.config.Permissions); err != nil {
		return err
	}

	return nil
}

// validateMetadata validates the file metadata and checksum
func (fs *FileStorage) validateMetadata(metadata StorageMetadata, manager *vault.VaultManager) error {
	// Check version compatibility
	if metadata.Version > 1 {
		return fmt.Errorf("unsupported file version: %d", metadata.Version)
	}

	// Check application identifier
	if metadata.Application != "vault-manager-v1" {
		return fmt.Errorf("invalid application identifier: %s", metadata.Application)
	}

	// Verify checksum
	managerData, err := json.Marshal(manager)
	if err != nil {
		return fmt.Errorf("failed to serialize manager for checksum: %w", err)
	}

	checksum := sha256.Sum256(managerData)
	checksumHex := hex.EncodeToString(checksum[:])

	if metadata.Checksum != checksumHex {
		return fmt.Errorf("checksum mismatch - file may be corrupted")
	}

	return nil
}

// cleanupOldBackups removes old backup files beyond MaxBackups
func (fs *FileStorage) cleanupOldBackups() error {
	entries, err := os.ReadDir(fs.config.BackupDir)
	if err != nil {
		return err
	}

	// Filter backup files and sort by modification time
	var backupFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			backupFiles = append(backupFiles, entry)
		}
	}

	// If we don't have too many backups, nothing to do
	if len(backupFiles) <= fs.config.MaxBackups {
		return nil
	}

	// Sort by modification time (oldest first)
	// Note: This is a simplified sort - in production you'd want proper sorting
	filesToDelete := len(backupFiles) - fs.config.MaxBackups

	for i := 0; i < filesToDelete; i++ {
		backupPath := filepath.Join(fs.config.BackupDir, backupFiles[i].Name())
		if err := os.Remove(backupPath); err != nil {
			return fmt.Errorf("failed to remove old backup %s: %w", backupPath, err)
		}
	}

	return nil
}

// ListBackups returns available backup files
func (fs *FileStorage) ListBackups() ([]string, error) {
	entries, err := os.ReadDir(fs.config.BackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var backups []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			backups = append(backups, entry.Name())
		}
	}

	return backups, nil
}

// RestoreFromBackup restores vault from a specific backup file
func (fs *FileStorage) RestoreFromBackup(backupName string) (*vault.VaultManager, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	backupPath := filepath.Join(fs.config.BackupDir, backupName)
	if _, err := os.Stat(backupPath); err != nil {
		return nil, fmt.Errorf("backup file not found: %s", backupName)
	}

	// Read backup file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	// Parse container
	var container StorageContainer
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to parse backup file: %w", err)
	}

	// Validate metadata
	if err := fs.validateMetadata(container.Metadata, container.Manager); err != nil {
		return nil, fmt.Errorf("backup validation failed: %w", err)
	}

	return container.Manager, nil
}

// GetStorageInfo returns information about the storage file
func (fs *FileStorage) GetStorageInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})

	if fs.Exists() {
		stat, err := os.Stat(fs.config.FilePath)
		if err != nil {
			return nil, err
		}

		info["file_path"] = fs.config.FilePath
		info["file_size"] = stat.Size()
		info["modified"] = stat.ModTime()
		info["permissions"] = stat.Mode()
	} else {
		info["exists"] = false
	}

	backups, err := fs.ListBackups()
	if err != nil {
		return nil, err
	}
	info["backup_count"] = len(backups)
	info["backup_dir"] = fs.config.BackupDir

	return info, nil
}
