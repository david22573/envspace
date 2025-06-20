package main

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

type ErrWrongPassword string

func (e ErrWrongPassword) Error() string {
	return string(e)
}

type KDFParams struct {
	Algorithm string `json:"algorithm"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory"`
	Threads   uint8  `json:"threads"`
	Length    uint32 `json:"length"`
}

type Vault struct {
	Key        string                `json:"key"`
	KDF        KDFParams             `json:"kdf"`
	Nonce      []byte                `json:"nonce"`
	Workspaces map[string]*Workspace `json:"workspaces"`

	Locked bool `json:"-"`
}

func NewVault() *Vault {
	v := &Vault{
		KDF: KDFParams{
			Algorithm: "argon2id",
			Salt:      nil,
			Time:      3,
			Memory:    64 * 1024,
			Threads:   4,
			Length:    32,
		},
		Workspaces: make(map[string]*Workspace),
	}
	v.generateSaltAndNonce()
	v.Lock()
	return v
}

func (v *Vault) Open() error {
	if v.Locked {
		return ErrWrongPassword("vault is locked, please unlock it first")
	}
	return nil
}

func (v *Vault) Lock() {
	v.Locked = true
}

func (v *Vault) Unlock(password string) error {
	if v.Locked {

		if password != v.Key {
			return ErrWrongPassword("provided password does not match the vault's lock password")
		}
		v.Locked = false
		return nil
	}
	return nil
}

func (v *Vault) generateSaltAndNonce() {
	salt := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(salt)
	rand.Read(nonce)
	v.KDF.Salt = salt
	v.Nonce = nonce
}

func deriveKey(password []byte, params KDFParams) ([]byte, error) {
	return argon2.IDKey(password, params.Salt, params.Time, params.Memory, params.Threads, params.Length), nil
}
