package main

type FileStore struct {
	Path  string
	vault *Vault
}

func NewFileStore(path string) *FileStore {
	v := NewVault()
	return &FileStore{Path: path, vault: v}
}

func (fs *FileStore) CreateVault() *Vault {
	fs.vault = NewVault()
	return fs.vault
}

func (fs *FileStore) ReadVault() *Vault {
	return fs.vault
}
