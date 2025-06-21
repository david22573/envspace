package storage_test

import (
	"path/filepath"
	"testing"

	"github.com/david22573/envspace/storage"
	"github.com/david22573/envspace/vault"
)

func createTestVaultManager(t *testing.T, password string) *vault.VaultManager {
	t.Helper()

	manager, err := vault.NewVaultManager(password)
	if err != nil {
		t.Fatalf("NewVaultManager failed: %v", err)
	}

	if err := manager.Unlock(password); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if err := manager.CreateVault("test-vault"); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	return manager
}

func TestFileStorage_SaveLoadRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.json")

	fs := storage.NewFileStorage(storage.FileStorageConfig{
		FilePath:    vaultPath,
		Permissions: 0600,
		AutoBackup:  true,
	})

	original := createTestVaultManager(t, "secret123")
	if err := fs.Save(original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if !fs.Exists() {
		t.Fatal("Expected file to exist after Save")
	}

	loaded, err := fs.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if err := loaded.Unlock("secret123"); err != nil {
		t.Fatalf("Unlock after load failed: %v", err)
	}

	vaults := loaded.ListVaults()
	if len(vaults) != 1 || vaults[0] != "test-vault" {
		t.Fatalf("Expected 1 vault 'test-vault', got: %v", vaults)
	}
}

func TestFileStorage_BackupAndRestore(t *testing.T) {
	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.json")
	backupDir := filepath.Join(tmp, "backups")

	fs := storage.NewFileStorage(storage.FileStorageConfig{
		FilePath:    vaultPath,
		BackupDir:   backupDir,
		MaxBackups:  5,
		Permissions: 0600,
		AutoBackup:  true,
	})

	original := createTestVaultManager(t, "password")
	if err := fs.Save(original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := fs.Backup(); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	backups, err := fs.ListBackups()
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups) == 0 {
		t.Fatal("Expected at least one backup")
	}

	restored, err := fs.RestoreFromBackup(backups[0])
	if err != nil {
		t.Fatalf("RestoreFromBackup failed: %v", err)
	}

	if err := restored.Unlock("password"); err != nil {
		t.Fatalf("Unlock restored manager failed: %v", err)
	}

	if len(restored.ListVaults()) != 1 {
		t.Errorf("Expected 1 vault in restored manager, got %d", len(restored.ListVaults()))
	}
}

func TestFileStorage_Delete(t *testing.T) {
	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.json")

	fs := storage.NewFileStorage(storage.FileStorageConfig{
		FilePath:    vaultPath,
		Permissions: 0600,
	})

	manager := createTestVaultManager(t, "pwd")
	if err := fs.Save(manager); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := fs.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if fs.Exists() {
		t.Fatal("Expected file to be deleted")
	}
}

func TestFileStorage_GetStorageInfo(t *testing.T) {
	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.json")
	backupDir := filepath.Join(tmp, "backups")

	fs := storage.NewFileStorage(storage.FileStorageConfig{
		FilePath:    vaultPath,
		BackupDir:   backupDir,
		Permissions: 0600,
		AutoBackup:  true,
	})

	manager := createTestVaultManager(t, "mypass")
	if err := fs.Save(manager); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if err := fs.Backup(); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	info, err := fs.GetStorageInfo()
	if err != nil {
		t.Fatalf("GetStorageInfo failed: %v", err)
	}

	if info["file_path"] != vaultPath {
		t.Errorf("Unexpected file_path: %v", info["file_path"])
	}
	if info["backup_count"].(int) == 0 {
		t.Error("Expected at least one backup")
	}
	if info["file_size"].(int64) <= 0 {
		t.Error("Expected non-zero file size")
	}
}
