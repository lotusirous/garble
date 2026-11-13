package literals

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"math/rand"
	"strconv"
	"testing"
)

// templateIdents returns every identifier spelled in the template's decode
// method, other than its receiver and the universe's predeclared names.
// None of them may reach a user package unrenamed.
func templateIdents(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "", decoderTemplateSource, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	idents := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "decode" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name != "v" && types.Universe.Lookup(id.Name) == nil {
				idents[id.Name] = true
			}
			return true
		})
	}
	if len(idents) == 0 {
		t.Fatal("template has no decode method")
	}
	return idents
}

func hiddenObfRand(seed int64) *obfRand {
	return newObfRand(rand.New(rand.NewSource(seed)), &ast.File{Name: ast.NewIdent("main")},
		func(_ *rand.Rand, name string) string { return "hidden_" + name })
}

func TestEmitDecoderNames(t *testing.T) {
	template := templateIdents(t)
	r := hiddenObfRand(1)
	decl := cipherVariants()[0].emitDecoder("hidden_decoder", newGeneratedNames(r))
	if decl.Recv != nil {
		t.Fatal("emitted decoder kept its receiver")
	}
	if decl.Name.Name != "hidden_decoder" {
		t.Fatalf("emitted decoder is named %q", decl.Name.Name)
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if n.Pos() != token.NoPos {
			t.Errorf("%T keeps template position %d", n, n.Pos())
		}
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := n.X.(*ast.Ident); ok && id.Name == "v" {
				t.Errorf("v.%s was not substituted", n.Sel.Name)
			}
		case *ast.Ident:
			if template[n.Name] {
				t.Errorf("template name %q reached the emitted decoder", n.Name)
			}
		}
		return true
	})
}

// TestEmitDecoderProbe builds the emitted decoders in a module declaring an
// old language version, and checks them against encode.
func TestEmitDecoderProbe(t *testing.T) {
	r := hiddenObfRand(1)
	owner := ownerKey{0x0123456789abcdef, 0xfedcba9876543210}
	var src bytes.Buffer
	src.WriteString("package main\n\n")
	var checks bytes.Buffer
	for i, v := range sampleVariants() {
		name := fmt.Sprintf("dec%d", i)
		if err := printer.Fprint(&src, token.NewFileSet(), v.emitDecoder(name, newGeneratedNames(r))); err != nil {
			t.Fatal(err)
		}
		src.WriteString("\n\n")
		for _, size := range []int{0, 1, 24, 300} {
			plain := make([]byte, size)
			r.rnd.Read(plain)
			ct, low, high := v.encode(r.rnd, plain, owner)
			call := fmt.Sprintf("%s(%s, %#x, %#x, %d, %d)", name, strconv.Quote(ct), owner[0], owner[1], low, high)
			want := strconv.Quote(string(plain))
			fmt.Fprintf(&checks, "\tif got := %s; string(got) != %s || len(got) != cap(got) {\n\t\tpanic(%q)\n\t}\n",
				call, want, fmt.Sprintf("%s size %d", name, size))
			if i == 0 && size == 24 {
				// A caller mutating its result must not change the next decode.
				fmt.Fprintf(&checks, "\tfirst := %s\n\tfirst[0] ^= 1\n\tif string(%s) != %s {\n\t\tpanic(\"aliasing\")\n\t}\n",
					call, call, want)
			}
		}
	}
	src.WriteString("func main() {\n")
	src.Write(checks.Bytes())
	src.WriteString("\tprintln(\"ok\")\n}\n")
	buildAndRunProbe(t, src.Bytes(), "1.12", "ok\n")
}
