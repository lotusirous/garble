// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"

	"golang.org/x/tools/go/ast/astutil"
	ah "mvdan.cc/garble/internal/asthelper"
)

// decoderTemplateSource is garble's own decoder source, so the decoder that
// garble tests is the one it emits.
//
//go:embed decoder_template.go
var decoderTemplateSource string

// emitDecoder returns the template's decode method as a top-level function
// called name, with the variant's constants substituted and every local and
// parameter renamed through names.
func (v cipherVariant) emitDecoder(name string, names *generatedNames) *ast.FuncDecl {
	// Parsing afresh gives every emitted copy its own nodes.
	file, err := parser.ParseFile(token.NewFileSet(), "decoder_template.go", decoderTemplateSource, parser.SkipObjectResolution)
	if err != nil {
		panic(err)
	}
	var decl *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "decode" {
			decl = fn
			break
		}
	}
	if decl == nil {
		panic("decoder template has no decode method")
	}
	recv := decl.Recv.List[0].Names[0].Name
	constants := map[string]int{"rotA": int(v.rotA), "rotB": int(v.rotB), "rounds": int(v.rounds)}
	astutil.Apply(decl.Body, func(c *astutil.Cursor) bool {
		sel, ok := c.Node().(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == recv {
			value, ok := constants[sel.Sel.Name]
			if !ok {
				panic(fmt.Sprintf("decoder template uses %s.%s", recv, sel.Sel.Name))
			}
			c.Replace(ah.IntLit(value))
			return false
		}
		return true
	}, nil)

	rename := func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && types.Universe.Lookup(id.Name) == nil {
			id.Name = names.name(id.Name)
		}
		return true
	}
	ast.Inspect(decl.Type, rename)
	ast.Inspect(decl.Body, rename)
	decl.Recv = nil
	decl.Doc = nil
	decl.Name = ast.NewIdent(name)
	zeroPositions(decl)
	return decl
}

var posType = reflect.TypeFor[token.Pos]()

// zeroPositions clears every position under node. Positions from another file
// set would make the printer misplace the user's comments around the node.
func zeroPositions(node ast.Node) {
	var zero func(reflect.Value)
	zero = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			// The template is parsed without objects, so the tree has no cycles.
			if !v.IsNil() {
				zero(v.Elem())
			}
		case reflect.Struct:
			for i := range v.NumField() {
				if field := v.Field(i); field.Type() == posType {
					field.SetInt(int64(token.NoPos))
				} else {
					zero(field)
				}
			}
		case reflect.Slice:
			for i := range v.Len() {
				zero(v.Index(i))
			}
		}
	}
	zero(reflect.ValueOf(node))
}
