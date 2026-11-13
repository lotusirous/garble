package literals

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestRepeatedStringDecoders(t *testing.T) {
	const source = `package main
var global = "repeated literal secret"
func first() {
 _ = "repeated literal secret"
 _ = "repeated " + "literal secret"
 _ = func() string { return "repeated literal secret" }
 _ = []byte("repeated literal secret")
 type bytes []byte
 _ = bytes("repeated literal secret")
 _ = []rune("repeated literal secret")
 _ = "different literal secret"
}
func second() string { return "repeated literal secret" }
func init() { _ = "repeated literal secret" }
var callback = func() string { return "repeated literal secret" }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "repeat.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object)}
	if _, err := new(types.Config).Check("main", fset, []*ast.File{file}, info); err != nil {
		t.Fatal(err)
	}
	originalCount := len(file.Decls)
	Obfuscate(rand.New(rand.NewSource(1)), file, info, nil, nil, nil, func(r *rand.Rand, base string) string { return fmt.Sprintf("%s%d", base, r.Uint64()) })
	decoders, entries := 0, 0
	for _, decl := range file.Decls[originalCount:] {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if strings.HasPrefix(fn.Name.Name, "literalDecoder") {
				decoders++
			} else if strings.HasPrefix(fn.Name.Name, "literalString") {
				entries++
			}
		}
	}
	// Every owner shares the file's decoder; only the keys are per owner.
	if decoders != 1 || entries != 1 {
		t.Fatalf("got %d decoders and %d string entries, want 1 and 1", decoders, entries)
	}
	checked := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue)}
	if _, err := new(types.Config).Check("main", fset, []*ast.File{file}, checked); err != nil {
		t.Fatal(err)
	}
	claimed := make(map[string]string)
	for _, decl := range file.Decls[:originalCount] {
		if gen, ok := decl.(*ast.GenDecl); ok {
			if spec := gen.Specs[0].(*ast.ValueSpec); spec.Names[0].Name == "global" {
				continue // The certified global calls its own factory directly.
			}
		}
		owner := "package"
		if fn, ok := decl.(*ast.FuncDecl); ok {
			owner = fn.Name.Name
		}
		var calls []string
		nodes := make(map[ast.Node]bool)
		ast.Inspect(decl, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if _, ok := call.Fun.(*ast.SelectorExpr); !ok || checked.TypeOf(call) != types.Typ[types.String] {
				return true
			}
			var text strings.Builder
			if err := printer.Fprint(&text, fset, call); err != nil {
				t.Fatal(err)
			}
			key := text.String()
			calls = append(calls, key)
			if previous, ok := claimed[key]; ok && (previous != owner || owner == "package") {
				t.Errorf("decoder shared between %s and %s", previous, owner)
			}
			claimed[key] = owner
			for n := range ast.Preorder(call) {
				if nodes[n] {
					t.Error("repeated calls share mutable AST nodes")
				}
				nodes[n] = true
			}
			return false
		})
		if owner == "first" {
			if len(calls) != 7 {
				t.Fatalf("got %d decoder calls, want 7", len(calls))
			}
			for _, call := range calls[1:6] {
				if call != calls[0] {
					t.Error("equal strings in one original function do not share a decoder and proxy arguments")
				}
			}
			if calls[6] == calls[0] {
				t.Error("different strings share a decoder")
			}
		} else if len(calls) != 1 {
			t.Errorf("owner %s has %d calls, want 1", owner, len(calls))
		}
	}
}

// TestCipherFilesInOnePackage checks that each file carries its own decoder
// and keys, so equal literals in two files of a package neither collide in
// generated names nor share a ciphertext.
func TestCipherFilesInOnePackage(t *testing.T) {
	const literal = "same literal in two files"
	fset := token.NewFileSet()
	var files []*ast.File
	for i := 1; i <= 2; i++ {
		file, err := parser.ParseFile(fset, fmt.Sprintf("file%d.go", i), fmt.Sprintf("package p\nvar s%d = %q\n", i, literal), parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	if _, err := new(types.Config).Check("p", fset, files, info); err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(1))
	ciphertexts := make([]map[string]bool, len(files))
	for i, file := range files {
		files[i] = Obfuscate(r, file, info, nil, nil, nil, func(r *rand.Rand, base string) string { return fmt.Sprintf("%s%d", base, r.Uint64()) })
		decoders := 0
		ciphertexts[i] = make(map[string]bool)
		ast.Inspect(files[i], func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.FuncDecl:
				if strings.HasPrefix(node.Name.Name, "literalDecoder") {
					decoders++
				}
			case *ast.BasicLit:
				if text, err := strconv.Unquote(node.Value); err == nil && node.Kind == token.STRING && len(text) >= cipherHeaderSize+len(literal) {
					ciphertexts[i][text] = true
				}
			}
			return true
		})
		if decoders != 1 {
			t.Fatalf("file %d has %d decoders, want 1", i+1, decoders)
		}
		if len(ciphertexts[i]) == 0 {
			t.Fatalf("file %d has no ciphertext", i+1)
		}
	}
	for text := range ciphertexts[0] {
		if ciphertexts[1][text] {
			t.Fatal("two files share a ciphertext")
		}
	}
	if _, err := new(types.Config).Check("p", fset, files, nil); err != nil {
		t.Fatal(err)
	}
}
