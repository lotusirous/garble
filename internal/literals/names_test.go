package literals

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand"
	"strings"
	"testing"
)

func TestDecodersObfuscateGeneratedNames(t *testing.T) {
	const literal = "long_enough_string"
	cases := []struct {
		name    string
		build   func(*obfRand)
		helpers int
	}{
		{"string", func(r *obfRand) { obfuscateString(r, literal) }, 0},
		{"slice", func(r *obfRand) { obfuscateBytes(r, false, []byte(literal), 0) }, 0},
		{"slice pointer", func(r *obfRand) { obfuscateBytes(r, true, []byte(literal), 0) }, 1},
		{"array", func(r *obfRand) { obfuscateBytes(r, false, []byte(literal), int64(len(literal))) }, 1},
		{"array pointer", func(r *obfRand) { obfuscateBytes(r, true, []byte(literal), int64(len(literal))) }, 1},
	}
	template := templateIdents(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := hiddenObfRand(1)
			tc.build(r)
			kinds := make(map[string]int)
			for _, decl := range r.liftedFuncs {
				fn := decl.(*ast.FuncDecl)
				for _, base := range []string{"literalDecoder", "literalString", "literalBytes"} {
					if strings.HasPrefix(fn.Name.Name, "hidden_"+base) {
						kinds[base]++
					}
				}
				ast.Inspect(decl, func(node ast.Node) bool {
					if id, ok := node.(*ast.Ident); ok && (template[id.Name] || id.Name == "slice" || id.Name == "array") {
						t.Errorf("generated identifier %q was not obfuscated", id.Name)
					}
					return true
				})
			}
			if kinds["literalDecoder"] != 1 || kinds["literalString"] != 1 || kinds["literalBytes"] != tc.helpers {
				t.Fatalf("lifted functions %v, want one decoder, one string entry and %d helpers", kinds, tc.helpers)
			}
		})
	}
}

// Each original function must reach only its own generated proxy declarations,
// including decoders for nested closures, methods and generic functions.
func TestFunctionOwnedProxyDispatchers(t *testing.T) {
	const source = `package main
var global = "global literal secret"
var callback = func() string { return "global callback secret" }
var initialized = first()
type receiver struct{}
func first() string { return "first literal secret" + string([]byte("another first secret")) }
func second() string { return "second literal secret" + func() string { return "nested literal secret" }() }
func (receiver) method() string { return "method literal secret" }
func generic[T any](v T) string { return "generic literal secret" }
func init() { global += "init literal secret" }
`
	// The file's decoder and its helpers hold no key material, so owners share them.
	shared := func(name string) bool {
		return strings.HasPrefix(name, "literalDecoder") || strings.HasPrefix(name, "literalString") || strings.HasPrefix(name, "literalBytes")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "owner.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	if _, err := new(types.Config).Check("owners", fset, []*ast.File{file}, info); err != nil {
		t.Fatal(err)
	}
	liftedNames := make(map[string]bool)
	originalCount := len(file.Decls)
	Obfuscate(rand.New(rand.NewSource(1)), file, info, nil, nil, nil, func(r *rand.Rand, base string) string {
		if strings.HasPrefix(base, "literalDecoder") || strings.HasPrefix(base, "literalString") {
			if liftedNames[base] {
				t.Errorf("lifted function base name reused: %s", base)
			}
			liftedNames[base] = true
		}
		return fmt.Sprintf("%s%d", base, r.Uint64())
	})
	// Recheck the generated AST, including uniqueness of lifted names and
	// the function types stored in the proxy trees.
	if _, err := new(types.Config).Check("owners", fset, []*ast.File{file}, nil); err != nil {
		t.Fatal(err)
	}
	decls := make(map[string]ast.Node)
	var owners []*ast.FuncDecl
	for i, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			if i < originalCount {
				owners = append(owners, decl)
			} else {
				decls[decl.Name.Name] = decl
			}
		case *ast.GenDecl:
			if i >= originalCount && decl.Tok == token.VAR {
				for _, spec := range decl.Specs {
					spec := spec.(*ast.ValueSpec)
					for _, name := range spec.Names {
						decls[name.Name] = spec
					}
				}
			}
		}
	}
	claimed := make(map[string]string)
	for _, fn := range owners {
		owner := fn.Name.Name
		seen := make(map[string]bool)
		var visit func(ast.Node)
		visit = func(node ast.Node) {
			ast.Inspect(node, func(node ast.Node) bool {
				id, ok := node.(*ast.Ident)
				if !ok || seen[id.Name] {
					return true
				}
				if decl := decls[id.Name]; decl != nil {
					seen[id.Name] = true
					if previous, ok := claimed[id.Name]; ok && previous != owner && !shared(id.Name) {
						t.Errorf("owners %s and %s share generated declaration %s", previous, owner, id.Name)
					}
					claimed[id.Name] = owner
					visit(decl)
				}
				return true
			})
		}
		visit(fn.Body)
		entries := 0
		for name := range seen {
			if strings.HasPrefix(name, "literalString") {
				entries++
			}
		}
		if entries != 1 {
			t.Errorf("owner %s reaches %d string entries, want 1", owner, entries)
		}
		if len(seen) == 0 {
			t.Errorf("owner %s has no hidden decoder", owner)
		}
	}
}

func TestGeneratedLocalNames(t *testing.T) {
	names := newGeneratedNames(hiddenObfRand(1))
	first := names.ident("data")
	if first.Name == "data" || names.ident("data").Name != first.Name {
		t.Fatalf("generated local was not consistently named: %q", first.Name)
	}
	if names.ident("other").Name == first.Name {
		t.Fatal("distinct generated locals have the same name")
	}
}
