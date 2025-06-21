package workspace

type Workspace struct {
	Name        string       `json:"name"`
	Environment *Environment `json:"environment,omitempty"`
}

func NewWorkspace(name string) *Workspace {
	return &Workspace{
		Name: name,
	}
}
