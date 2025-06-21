package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/hkdf"
)

type VaultID string

type ErrVaultLocked string

func (e ErrVaultLocked) Error() string { return string(e) }

type ErrInvalidHMAC string

func (e ErrInvalidHMAC) Error() string { return string(e) }

// VaultMetadata contains public information about the vault
type VaultMetadata struct {
	ID            VaultID   `json:"id"`
	Version       int       `json:"version"`
	Created       time.Time `json:"created"`
	Modified      time.Time `json:"modified"`
	Algorithm     string    `json:"algorithm"`
	KeyDerivation string    `json:"key_derivation"`
}

// VaultEntry represents a single encrypted item in the vault
type VaultEntry struct {
	ID         string    `json:"id"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
	HMAC       []byte    `json:"hmac"`
	Created    time.Time `json:"created"`
	Modified   time.Time `json:"modified"`
}

// Vault represents an individual vault with its own derived key
type Vault struct {
	Metadata VaultMetadata         `json:"metadata"`
	Entries  map[string]VaultEntry `json:"entries"`

	// Runtime state - not serialized
	locked   bool   `json:"-"`
	vaultKey []byte `json:"-"`
}

// NewVault creates a new vault with the given ID
func NewVault(id VaultID) *Vault {
	return &Vault{
		Metadata: VaultMetadata{
			ID:            id,
			Version:       1,
			Created:       time.Now(),
			Modified:      time.Now(),
			Algorithm:     "aes-256-gcm",
			KeyDerivation: "hkdf-sha256",
		},
		Entries: make(map[string]VaultEntry),
		locked:  true,
	}
}

// Unlock derives the vault key from the master key using HKDF
func (v *Vault) Unlock(masterKey []byte) error {
	if len(masterKey) == 0 {
		return errors.New("master key cannot be empty")
	}

	// Derive vault-specific key using HKDF
	// Context: "vault-key" + vault ID ensures unique keys per vault
	info := append([]byte("vault-key:"), []byte(v.Metadata.ID)...)

	hkdfReader := hkdf.New(sha256.New, masterKey, nil, info)
	vaultKey := make([]byte, 32) // 256-bit key for AES-256

	if _, err := hkdfReader.Read(vaultKey); err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	v.vaultKey = vaultKey
	v.locked = false
	return nil
}

// Lock clears the vault key from memory
func (v *Vault) Lock() {
	if v.vaultKey != nil {
		// Zero out the key material
		for i := range v.vaultKey {
			v.vaultKey[i] = 0
		}
		v.vaultKey = nil
	}
	v.locked = true
}

// IsLocked returns whether the vault is currently locked
func (v *Vault) IsLocked() bool {
	return v.locked || v.vaultKey == nil
}

// Store encrypts and stores data in the vault with the given entry ID
func (v *Vault) Store(entryID string, data []byte) error {
	if v.IsLocked() {
		return ErrVaultLocked("vault must be unlocked before storing data")
	}

	// Generate unique nonce for this entry
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext, err := v.encrypt(nonce, data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Compute HMAC of ciphertext
	mac := v.computeHMAC(ciphertext)

	// Store the entry
	now := time.Now()
	entry := VaultEntry{
		ID:         entryID,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		HMAC:       mac,
		Created:    now,
		Modified:   now,
	}

	// Update existing entry's created time if it exists
	if existing, exists := v.Entries[entryID]; exists {
		entry.Created = existing.Created
	}

	v.Entries[entryID] = entry
	v.Metadata.Modified = now
	return nil
}

// Retrieve decrypts and returns data from the vault
func (v *Vault) Retrieve(entryID string) ([]byte, error) {
	if v.IsLocked() {
		return nil, ErrVaultLocked("vault must be unlocked before retrieving data")
	}

	entry, exists := v.Entries[entryID]
	if !exists {
		return nil, fmt.Errorf("entry %s not found", entryID)
	}

	// Verify HMAC
	expectedMAC := v.computeHMAC(entry.Ciphertext)
	if !hmac.Equal(entry.HMAC, expectedMAC) {
		return nil, ErrInvalidHMAC("HMAC verification failed - data may be corrupted")
	}

	// Decrypt the data
	plaintext, err := v.decrypt(entry.Nonce, entry.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Delete removes an entry from the vault
func (v *Vault) Delete(entryID string) error {
	if v.IsLocked() {
		return ErrVaultLocked("vault must be unlocked before deleting data")
	}

	if _, exists := v.Entries[entryID]; !exists {
		return fmt.Errorf("entry %s not found", entryID)
	}

	delete(v.Entries, entryID)
	v.Metadata.Modified = time.Now()
	return nil
}

// ListEntries returns all entry IDs in the vault
func (v *Vault) ListEntries() []string {
	entries := make([]string, 0, len(v.Entries))
	for id := range v.Entries {
		entries = append(entries, id)
	}
	return entries
}

// encrypt encrypts data using AES-GCM with the vault's key
func (v *Vault) encrypt(nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.vaultKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// decrypt decrypts data using AES-GCM with the vault's key
func (v *Vault) decrypt(nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.vaultKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// computeHMAC computes HMAC-SHA256 of the data using the vault's key
func (v *Vault) computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, v.vaultKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// MarshalJSON customizes JSON serialization to exclude runtime state
func (v *Vault) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Metadata VaultMetadata         `json:"metadata"`
		Entries  map[string]VaultEntry `json:"entries"`
	}{
		Metadata: v.Metadata,
		Entries:  v.Entries,
	})
}

// UnmarshalJSON customizes JSON deserialization to set proper locked state
func (v *Vault) UnmarshalJSON(data []byte) error {
	type vaultAlias Vault
	alias := (*vaultAlias)(v)

	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	// Ensure vault starts in locked state
	v.locked = true
	v.vaultKey = nil

	return nil
}
