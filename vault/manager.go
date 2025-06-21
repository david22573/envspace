package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

type ErrWrongPassword string

func (e ErrWrongPassword) Error() string { return string(e) }

type ErrVaultNotFound string

func (e ErrVaultNotFound) Error() string { return string(e) }

// MasterKeyParams defines the Argon2id parameters for master key derivation
type MasterKeyParams struct {
	Algorithm string `json:"algorithm"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory"`
	Threads   uint8  `json:"threads"`
	Length    uint32 `json:"length"`
}

// ManagerMetadata contains information about the vault manager
type ManagerMetadata struct {
	Version    int             `json:"version"`
	Created    time.Time       `json:"created"`
	Modified   time.Time       `json:"modified"`
	KeyParams  MasterKeyParams `json:"key_params"`
	VaultCount int             `json:"vault_count"`
}

// VaultManager manages multiple vaults with a single master password
type VaultManager struct {
	Metadata   ManagerMetadata    `json:"metadata"`
	WrappedKey []byte             `json:"wrapped_key"` // Master key encrypted with password
	VaultData  map[VaultID][]byte `json:"vault_data"`  // Serialized vault data

	// Runtime state - not serialized
	mutex     sync.RWMutex       `json:"-"`
	masterKey []byte             `json:"-"`
	vaults    map[VaultID]*Vault `json:"-"`
	locked    bool               `json:"-"`
}

// NewVaultManager creates a new vault manager with the given master password
func NewVaultManager(masterPassword string) (*VaultManager, error) {
	if len(masterPassword) == 0 {
		return nil, errors.New("master password cannot be empty")
	}

	// Generate salt for master key derivation
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random master key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	manager := &VaultManager{
		Metadata: ManagerMetadata{
			Version:  1,
			Created:  time.Now(),
			Modified: time.Now(),
			KeyParams: MasterKeyParams{
				Algorithm: "argon2id",
				Salt:      salt,
				Time:      3,
				Memory:    64 * 1024, // 64 MB
				Threads:   4,
				Length:    32,
			},
			VaultCount: 0,
		},
		VaultData: make(map[VaultID][]byte),
		vaults:    make(map[VaultID]*Vault),
		locked:    true,
	}

	// Derive key from password and wrap the master key
	if err := manager.wrapMasterKey(masterPassword, masterKey); err != nil {
		return nil, fmt.Errorf("failed to wrap master key: %w", err)
	}

	return manager, nil
}

// Unlock derives the master key from password and unlocks all vaults
func (vm *VaultManager) Unlock(masterPassword string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Derive key from password
	passwordKey, err := vm.derivePasswordKey(masterPassword)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	// Unwrap master key
	masterKey, err := vm.unwrapMasterKey(passwordKey)
	if err != nil {
		return ErrWrongPassword("invalid master password")
	}

	vm.masterKey = masterKey
	vm.locked = false

	// Load and unlock all vaults
	if err := vm.loadVaults(); err != nil {
		vm.Lock() // Clean up on failure
		return fmt.Errorf("failed to load vaults: %w", err)
	}

	return nil
}

// Lock clears the master key and locks all vaults
func (vm *VaultManager) Lock() {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Lock all individual vaults
	for _, vault := range vm.vaults {
		vault.Lock()
	}

	// Clear master key
	if vm.masterKey != nil {
		for i := range vm.masterKey {
			vm.masterKey[i] = 0
		}
		vm.masterKey = nil
	}

	vm.locked = true
}

// IsLocked returns whether the manager is currently locked
func (vm *VaultManager) IsLocked() bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()
	return vm.locked || vm.masterKey == nil
}

// CreateVault creates a new vault with the given ID
func (vm *VaultManager) CreateVault(id VaultID) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.locked {
		return errors.New("manager must be unlocked before creating vaults")
	}

	if _, exists := vm.vaults[id]; exists {
		return fmt.Errorf("vault %s already exists", id)
	}

	// Create new vault
	vault := NewVault(id)

	// Unlock vault with master key
	if err := vault.Unlock(vm.masterKey); err != nil {
		return fmt.Errorf("failed to unlock new vault: %w", err)
	}

	vm.vaults[id] = vault
	vm.Metadata.VaultCount++
	vm.Metadata.Modified = time.Now()

	return nil
}

// GetVault returns a vault by ID (must be unlocked)
func (vm *VaultManager) GetVault(id VaultID) (*Vault, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	if vm.locked {
		return nil, errors.New("manager must be unlocked before accessing vaults")
	}

	vault, exists := vm.vaults[id]
	if !exists {
		return nil, ErrVaultNotFound(fmt.Sprintf("vault %s not found", id))
	}

	return vault, nil
}

// DeleteVault removes a vault by ID
func (vm *VaultManager) DeleteVault(id VaultID) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.locked {
		return errors.New("manager must be unlocked before deleting vaults")
	}

	vault, exists := vm.vaults[id]
	if !exists {
		return ErrVaultNotFound(fmt.Sprintf("vault %s not found", id))
	}

	// Lock and remove vault
	vault.Lock()
	delete(vm.vaults, id)
	delete(vm.VaultData, id)

	vm.Metadata.VaultCount--
	vm.Metadata.Modified = time.Now()

	return nil
}

// ListVaults returns all vault IDs
func (vm *VaultManager) ListVaults() []VaultID {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vaultIDs := make([]VaultID, 0, len(vm.vaults))
	for id := range vm.vaults {
		vaultIDs = append(vaultIDs, id)
	}
	return vaultIDs
}

// Save serializes all vaults and prepares for storage
func (vm *VaultManager) Save() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.locked {
		return errors.New("manager must be unlocked before saving")
	}

	// Serialize all vaults
	for id, vault := range vm.vaults {
		data, err := json.Marshal(vault)
		if err != nil {
			return fmt.Errorf("failed to serialize vault %s: %w", id, err)
		}
		vm.VaultData[id] = data
	}

	vm.Metadata.Modified = time.Now()
	return nil
}

// derivePasswordKey derives a key from the master password using Argon2id
func (vm *VaultManager) derivePasswordKey(password string) ([]byte, error) {
	params := vm.Metadata.KeyParams
	if params.Algorithm != "argon2id" {
		return nil, errors.New("unsupported key derivation algorithm")
	}

	return argon2.IDKey(
		[]byte(password),
		params.Salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.Length,
	), nil
}

// wrapMasterKey encrypts the master key with the password-derived key
func (vm *VaultManager) wrapMasterKey(password string, masterKey []byte) error {
	passwordKey, err := vm.derivePasswordKey(password)
	if err != nil {
		return err
	}

	// Simple XOR wrapping (in production, use AES-GCM or similar)
	wrapped := make([]byte, len(masterKey))
	for i := range masterKey {
		wrapped[i] = masterKey[i] ^ passwordKey[i%len(passwordKey)]
	}

	vm.WrappedKey = wrapped
	return nil
}

// unwrapMasterKey decrypts the master key using the password-derived key
func (vm *VaultManager) unwrapMasterKey(passwordKey []byte) ([]byte, error) {
	if len(vm.WrappedKey) == 0 {
		return nil, errors.New("no wrapped key found")
	}

	// Simple XOR unwrapping
	masterKey := make([]byte, len(vm.WrappedKey))
	for i := range vm.WrappedKey {
		masterKey[i] = vm.WrappedKey[i] ^ passwordKey[i%len(passwordKey)]
	}

	// Verify key is valid by testing a known derivation
	// In production, store a verification hash
	testKey := make([]byte, 32)
	copy(testKey, masterKey)

	// Simple validation - check if key is all zeros (failed unwrap)
	allZeros := true
	for _, b := range masterKey {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return nil, errors.New("invalid master key")
	}

	return masterKey, nil
}

// loadVaults deserializes and unlocks all stored vaults
func (vm *VaultManager) loadVaults() error {
	for id, data := range vm.VaultData {
		vault := &Vault{}
		if err := json.Unmarshal(data, vault); err != nil {
			return fmt.Errorf("failed to deserialize vault %s: %w", id, err)
		}

		// Unlock vault with master key
		if err := vault.Unlock(vm.masterKey); err != nil {
			return fmt.Errorf("failed to unlock vault %s: %w", id, err)
		}

		vm.vaults[id] = vault
	}

	return nil
}

// ChangePassword changes the master password
func (vm *VaultManager) ChangePassword(oldPassword, newPassword string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.locked {
		return errors.New("manager must be unlocked before changing password")
	}

	// Verify old password
	oldPasswordKey, err := vm.derivePasswordKey(oldPassword)
	if err != nil {
		return err
	}

	testKey, err := vm.unwrapMasterKey(oldPasswordKey)
	if err != nil {
		return ErrWrongPassword("incorrect old password")
	}

	// Verify it matches current master key
	if subtle.ConstantTimeCompare(testKey, vm.masterKey) != 1 {
		return ErrWrongPassword("incorrect old password")
	}

	// Generate new salt for new password
	newSalt := make([]byte, 32)
	if _, err := rand.Read(newSalt); err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	// Update key parameters
	vm.Metadata.KeyParams.Salt = newSalt
	vm.Metadata.Modified = time.Now()

	// Re-wrap master key with new password
	if err := vm.wrapMasterKey(newPassword, vm.masterKey); err != nil {
		return fmt.Errorf("failed to wrap key with new password: %w", err)
	}

	return nil
}

// MarshalJSON customizes JSON serialization to exclude runtime state
func (vm *VaultManager) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Metadata   ManagerMetadata    `json:"metadata"`
		WrappedKey []byte             `json:"wrapped_key"`
		VaultData  map[VaultID][]byte `json:"vault_data"`
	}{
		Metadata:   vm.Metadata,
		WrappedKey: vm.WrappedKey,
		VaultData:  vm.VaultData,
	})
}

// UnmarshalJSON customizes JSON deserialization to set proper locked state
func (vm *VaultManager) UnmarshalJSON(data []byte) error {
	type managerAlias VaultManager
	alias := (*managerAlias)(vm)

	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	// Initialize runtime state
	vm.vaults = make(map[VaultID]*Vault)
	vm.locked = true
	vm.masterKey = nil

	return nil
}
