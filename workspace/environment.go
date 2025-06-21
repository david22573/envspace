package workspace

import "maps"

type VariableMap map[string]string
type Environment struct {
	Variables VariableMap `json:"variables"`
}

func NewEnvironment() *Environment {
	return &Environment{
		Variables: make(VariableMap),
	}
}
func (e *Environment) SetVariable(name, value string) {
	e.Variables[name] = value
}
func (e *Environment) GetVariable(name string) (string, bool) {
	value, exists := e.Variables[name]
	return value, exists
}

func (e *Environment) DeleteVariable(name string) {
	delete(e.Variables, name)
}

func (e *Environment) Clear() {
	e.Variables = make(VariableMap)
}
func (e *Environment) Clone() *Environment {
	clone := NewEnvironment()
	clone.Variables = make(VariableMap)
	clone.Variables = maps.Clone(clone.Variables)
	return clone
}

func (e *Environment) Merge(other *Environment) {
	if other == nil {
		return
	}
	maps.Copy(e.Variables, other.Variables)
}
func (e *Environment) MergeWith(other *Environment) *Environment {
	if other == nil {
		return e.Clone()
	}
	clone := e.Clone()
	clone.Merge(other)
	return clone
}
