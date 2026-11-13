// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	mathrand "math/rand"
	"strconv"
	"unicode/utf8"

	"golang.org/x/tools/go/ast/astutil"
	ah "mvdan.cc/garble/internal/asthelper"
)

// MinSize is the lower bound limit, of the size of string-like literals
// which we will obfuscate. This is needed in order for binary size to stay relatively
// moderate, this also decreases the likelihood for performance slowdowns.
const MinSize = 8

const (
	// minStringJunkBytes defines the minimum number of junk bytes to prepend or append during string obfuscation.
	minStringJunkBytes = 2
	// maxStringJunkBytes defines the maximum number of junk bytes to prepend or append during string obfuscation.
	maxStringJunkBytes = 8
)

// NameProviderFunc defines a function type that generates a string based on a random source and a base name.
type NameProviderFunc func(rand *mathrand.Rand, baseName string) string

// EmbeddedValue bypasses the minimum size threshold for resolved //go:embed data.
type EmbeddedValue struct {
	Data   []byte
	String bool
}

// GlobalInit certifies a generated side-effect-free factory for one global.
// The declaration name is retained by pointer so subsequent renaming is reflected.
type GlobalInit struct {
	Global  *ast.Ident
	Factory string
}

// Obfuscate replaces literals with obfuscated anonymous functions.
func Obfuscate(rand *mathrand.Rand, file *ast.File, info *types.Info, linkStrings map[*types.Var]string, embeds map[ast.Expr]EmbeddedValue, staticInits map[*types.Var]bool, nameFunc NameProviderFunc) *ast.File {
	file, _ = ObfuscateWithGlobalInits(rand, file, info, linkStrings, embeds, staticInits, nameFunc)
	return file
}

// staticInits holds variables whose initializer must stay a compile-time
// constant, such as the compiler's read-only coverage metadata variable.
func ObfuscateWithGlobalInits(rand *mathrand.Rand, file *ast.File, info *types.Info, linkStrings map[*types.Var]string, embeds map[ast.Expr]EmbeddedValue, staticInits map[*types.Var]bool, nameFunc NameProviderFunc, summaries ...map[string]bool) (*ast.File, []GlobalInit) {
	var constructors map[string]bool
	if len(summaries) != 0 {
		constructors = summaries[0]
	} else {
		constructors = ConstructorSummaries([]*ast.File{file}, info, nil)
	}
	or := newObfRand(rand, nameFunc)
	var globalInits []GlobalInit
	// Package initializers, including their function literals, keep a shared
	// dispatcher. Each original function declaration gets a separate tree so
	// a live function cannot retain another function's key half.
	packageDispatcher := or.proxyDispatcher
	dispatchers := []*proxyDispatcher{packageDispatcher}
	pre := func(cursor *astutil.Cursor) bool {
		switch node := cursor.Node().(type) {
		case *ast.FuncDecl:
			// Obfuscating literals can push the stack frame over the //go:nosplit limit,
			// which is just 800 bytes. These funcs are mostly in the runtime,
			// so obfuscating strings in these is less important in any case.
			if node.Doc != nil {
				for _, comment := range node.Doc.List {
					dir, ok := ast.ParseDirective(token.NoPos, comment.Text)
					if ok && dir.Tool == "go" && dir.Name == "nosplit" {
						return false
					}
				}
			}
			// Cache decoder recipes only within an original function, including
			// its nested closures, never across package initializer scopes.
			or.stringCalls = make(map[string]*ast.CallExpr)
			owner := len(dispatchers)
			or.proxyDispatcher = newProxyDispatcher(rand, func(rand *mathrand.Rand, base string) string {
				return nameFunc(rand, fmt.Sprintf("literalOwner%d_%s", owner, base))
			})
			dispatchers = append(dispatchers, or.proxyDispatcher)
		case *ast.GenDecl:
			// constants are obfuscated by replacing all references with the obfuscated value
			if node.Tok == token.CONST {
				return false
			}
		case *ast.ValueSpec:
			if skipLiteralInit(node, info, staticInits) {
				// Keep the initializer static and do not descend into it,
				// as any decoded expression would run at initialization time.
				return false
			}
			hadValues := len(node.Values) > 0
			for i, name := range node.Names {
				obj := info.Defs[name].(*types.Var)
				value, ok := linkStrings[obj]
				if !ok || !types.Identical(obj.Type(), types.Typ[types.String]) {
					continue
				}
				if len(node.Values) == 0 {
					for range node.Names {
						node.Values = append(node.Values, &ast.BasicLit{Kind: token.STRING, Value: `""`})
					}
				} else if hadValues && (len(node.Values) != len(node.Names) ||
					(info.Types[node.Values[i]].Value == nil && !isEmbeddedPlaceholder(node.Values[i], embeds))) {
					// Like cmd/link, leave non-constant initializers alone. An
					// embedded variable has no initializer in the source, so -X
					// still applies to it; see isEmbeddedPlaceholder.
					continue
				}
				expr := ast.Expr(&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(value)})
				if len(value) >= MinSize {
					expr = obfuscateString(or, value)
				}
				node.Values[i] = withPos(expr, name.Pos()).(ast.Expr)
			}
			if len(node.Names) == 1 && len(node.Values) == 1 && node.Names[0].Name != "_" {
				obj := info.Defs[node.Names[0]].(*types.Var)
				value := node.Values[0]
				var constructorType ast.Expr
				if _, ok := ast.Unparen(value).(*ast.CallExpr); ok && obj.Parent() == obj.Pkg().Scope() && constructorVariables(value, info, nil) && constructorExpr(value, info, nil, func(fn *types.Func) bool { return constructors[fn.FullName()] }) {
					found := false
					ast.Inspect(value, func(n ast.Node) bool {
						if e, ok := n.(ast.Expr); ok {
							v := info.Types[e]
							if v.Type == types.Typ[types.String] && v.Value != nil && v.Value.Kind() == constant.String {
								size := len(constant.StringVal(v.Value))
								found = found || size >= MinSize
							}
						}
						return true
					})
					if found {
						constructorType = constructorResult(file, info, obj.Type())
					}
				}
				if obj.Parent() == obj.Pkg().Scope() && types.Identical(obj.Type(), info.TypeOf(value)) && (pureStringInit(value, info) || constructorType != nil) {
					resultType := ast.Expr(ast.NewIdent("string"))
					if constructorType != nil {
						resultType = constructorType
					}
					if lit, ok := ast.Unparen(value).(*ast.CompositeLit); ok {
						resultType = lit.Type
						if array, ok := resultType.(*ast.ArrayType); ok {
							if _, ok := array.Len.(*ast.Ellipsis); ok {
								resultType = &ast.ArrayType{Len: ah.IntLit(int(obj.Type().Underlying().(*types.Array).Len())), Elt: array.Elt}
							}
						}
					}
					factory := or.globalLiteralFactory(resultType, func() ast.Expr {
						return astutil.Apply(value, func(c *astutil.Cursor) bool {
							expr, ok := c.Node().(ast.Expr)
							if !ok || info.Types[expr].Value == nil {
								return true
							}
							v := info.Types[expr]
							if v.Type == types.Typ[types.String] && v.Value.Kind() == constant.String {
								text := constant.StringVal(v.Value)
								if len(text) >= MinSize {
									c.Replace(withPos(obfuscateString(or, text), expr.Pos()))
									return false
								}
							}
							return v.Value.Kind() == constant.String
						}, nil).(ast.Expr)
					})
					globalInits = append(globalInits, GlobalInit{Global: node.Names[0], Factory: factory})
					node.Values[0] = withPos(ah.CallExprByName(factory), value.Pos()).(ast.Expr)
					return false
				}
			}

		case ast.Expr:
			if value, ok := embeds[node]; ok {
				var replacement ast.Node
				if value.String {
					replacement = obfuscateString(or, string(value.Data))
				} else {
					replacement = obfuscateBytes(or, false, value.Data, 0)
				}
				cursor.Replace(withPos(replacement, node.Pos()))
				return false
			}
			// A constant string converted to a byte or rune slice has an
			// exact capacity. Decoding first can make the allocation larger.
			if call, ok := node.(*ast.CallExpr); ok && len(call.Args) == 1 {
				if slice, ok := info.TypeOf(call.Fun).Underlying().(*types.Slice); ok && (slice.Elem() == types.Universe.Lookup("byte").Type() || slice.Elem() == types.Universe.Lookup("rune").Type()) {
					elem := slice.Elem()
					if value := info.Types[call.Args[0]].Value; value != nil && value.Kind() == constant.String {
						text := constant.StringVal(value)
						if len(text) >= MinSize {
							size := len(text)
							if elem == types.Universe.Lookup("rune").Type() {
								size = utf8.RuneCountInString(text)
							}
							name := or.nameFunc(or.rnd, "literalSlice")
							result := ast.NewIdent(name)
							converted := ah.CallExpr(call.Fun, obfuscateString(or, text))
							body := ah.BlockStmt(
								ah.AssignDefineStmt(result, converted),
								ah.ReturnStmt(&ast.SliceExpr{
									X:    ast.NewIdent(name),
									High: ah.IntLit(size),
									Max:  ah.IntLit(size),
								}),
							)
							cursor.Replace(withPos(ah.LambdaCall(nil, call.Fun, body, nil), node.Pos()))
							return false
						}
					}
				}
			}
			// Rewrite &[]byte{...} as a whole on the way down. Rewriting the
			// composite literal on its own would leave behind &(decoder()),
			// which is not addressable, and parentheses in the input would
			// hide the literal from a check on the way up.
			//
			// See issue #520.
			if unary, ok := node.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				if lit, ok := ast.Unparen(unary.X).(*ast.CompositeLit); ok {
					if newNode := handleCompositeLiteral(or, true, lit, info); newNode != nil {
						cursor.Replace(newNode)
						return false
					}
				}
			}

			// The compiler folds constant expressions, so only the outermost
			// one exists at run time. Rewrite that one and stop descending,
			// rather than also rewriting its operands into dead decoders.
			typeAndValue := info.Types[node]
			if typeAndValue.Value == nil {
				break
			}
			if typeAndValue.Value.Kind() != constant.String {
				// Constants of other kinds, such as len or unsafe.Sizeof, do
				// not evaluate their operands at all. Rewriting them would be
				// useless, and would stop uses which require a constant, such
				// as array lengths or keyed indexes, from compiling.
				return false
			}
			byteStringArg := false
			if typeAndValue.Type == types.Typ[types.UntypedString] {
				if call, ok := cursor.Parent().(*ast.CallExpr); ok && len(call.Args) == 2 && call.Args[1] == node {
					if ident, ok := call.Fun.(*ast.Ident); ok {
						if builtin, ok := info.Uses[ident].(*types.Builtin); ok &&
							(builtin.Name() == "copy" || builtin.Name() == "append" && call.Ellipsis.IsValid()) {
							if slice, ok := info.TypeOf(call.Args[0]).Underlying().(*types.Slice); ok && slice.Elem() == types.Universe.Lookup("byte").Type() {
								byteStringArg = true
							}
						}
					}
				}
			}
			if typeAndValue.Type == types.Typ[types.String] || byteStringArg {
				value := constant.StringVal(typeAndValue.Value)
				if len(value) >= MinSize {
					cursor.Replace(withPos(obfuscateString(or, value), node.Pos()))
					return false
				}
			}
			// Keep descending: a string constant we left alone, such as one
			// below MinSize or one of a named type, may still have operands
			// which we can rewrite.
		}
		return true
	}

	post := func(cursor *astutil.Cursor) bool {
		if _, ok := cursor.Node().(*ast.FuncDecl); ok {
			or.proxyDispatcher = packageDispatcher
			or.stringCalls = nil
		}
		// Here we handle the plain []byte{...} or [4]byte{...} value form.
		// The pointer form was already replaced on the way down; a literal
		// which we declined there is declined here just the same.
		if lit, ok := cursor.Node().(*ast.CompositeLit); ok {
			if newNode := handleCompositeLiteral(or, false, lit, info); newNode != nil {
				cursor.Replace(newNode)
			}
		}
		return true
	}

	newFile := astutil.Apply(file, pre, post).(*ast.File)
	newFile.Decls = append(newFile.Decls, or.liftedFuncs...)
	for _, dispatcher := range dispatchers {
		dispatcher.AddToFile(newFile)
	}
	return newFile, globalInits
}

// skipLiteralInit reports whether any name declared by spec must keep a static
// initializer. The compiler marks its coverage metadata variable read-only and
// passes that symbol's address to the runtime, so a decoded initializer would
// be stored into read-only data and fault at startup.
func skipLiteralInit(spec *ast.ValueSpec, info *types.Info, staticInits map[*types.Var]bool) bool {
	if len(staticInits) == 0 {
		return false
	}
	for _, name := range spec.Names {
		if obj, ok := info.Defs[name].(*types.Var); ok && staticInits[obj] {
			return true
		}
	}
	return false
}

// pureStringInit admits strings and aggregates with constant leaves.
// Even unevaluated references to variables must retain their init dependencies.
func pureStringInit(expr ast.Expr, info *types.Info) bool {
	found := false
	var pure func(ast.Expr) bool
	pure = func(expr ast.Expr) bool {
		if value := info.Types[expr]; value.Value != nil {
			// Named string conversions can contain independently obfuscated operands.
			if value.Value.Kind() == constant.String && value.Type != types.Typ[types.String] {
				return false
			}
			if value.Type == types.Typ[types.String] && value.Value.Kind() == constant.String {
				size := len(constant.StringVal(value.Value))
				found = found || size >= MinSize
			}
			return true
		}
		nested, ok := ast.Unparen(expr).(*ast.CompositeLit)
		if !ok {
			return false
		}
		switch info.TypeOf(nested).Underlying().(type) {
		case *types.Array, *types.Struct, *types.Map:
		default:
			return false
		}
		for _, elem := range nested.Elts {
			if keyed, ok := elem.(*ast.KeyValueExpr); ok {
				if _, isMap := info.TypeOf(nested).Underlying().(*types.Map); isMap && !pure(keyed.Key) {
					return false
				}
				elem = keyed.Value
			}
			if !pure(elem) {
				return false
			}
		}
		return true
	}
	noVars := true
	ast.Inspect(expr, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && !info.Types[call.Fun].IsType() {
			if ident, ok := call.Fun.(*ast.Ident); !ok {
				noVars = false
			} else if _, ok := info.Uses[ident].(*types.Builtin); !ok {
				noVars = false
			}
		}
		if ident, ok := node.(*ast.Ident); ok {
			if obj, ok := info.Uses[ident].(*types.Var); ok {
				// Field keys are variables too, but are not evaluated references.
				noVars = noVars && obj.IsField()
			}
		}
		return true
	})
	return noVars && pure(expr) && found
}

// The proxy roots are local to the factory, so no unconditional package-level
// initialization can retain a dead global's key half or change init dependencies.
func (r *obfRand) globalLiteralFactory(resultType ast.Expr, value func() ast.Expr) string {
	name := r.nextLiftedFuncName("literalGlobal")
	shared := r.proxyDispatcher
	r.proxyDispatcher = newProxyDispatcher(r.rnd, func(rand *mathrand.Rand, base string) string {
		return r.nameFunc(rand, name+base)
	})
	call := value()
	locals := &ast.File{}
	r.proxyDispatcher.addToFile(locals, true)
	r.proxyDispatcher = shared
	body := &ast.BlockStmt{}
	for _, decl := range locals.Decls {
		body.List = append(body.List, &ast.DeclStmt{Decl: decl})
	}
	body.List = append(body.List, ah.ReturnStmt(call))
	r.liftedFuncs = append(r.liftedFuncs, &ast.FuncDecl{
		Name: ast.NewIdent(name),
		Type: &ast.FuncType{Params: &ast.FieldList{}, Results: &ast.FieldList{List: []*ast.Field{{Type: resultType}}}},
		Body: body,
	})
	return name
}

type obfRand struct {
	rnd             *mathrand.Rand
	nameFunc        NameProviderFunc
	liftedFuncSeq   int
	liftedFuncs     []ast.Decl
	proxyDispatcher *proxyDispatcher
	stringCalls     map[string]*ast.CallExpr

	// The file's cipher and its decoders, created by the first literal.
	cipher                      *cipherVariant
	bytesDecoder, stringDecoder string
	byteHelpers                 map[byteHelperKey]string
}

func newObfRand(rand *mathrand.Rand, nameFunc NameProviderFunc) *obfRand {
	return &obfRand{
		rnd:             rand,
		nameFunc:        nameFunc,
		proxyDispatcher: newProxyDispatcher(rand, nameFunc),
	}
}

// generatedNames assigns each decoder-local name before building its AST.
// References receive fresh Ident nodes with the same generated spelling.
type generatedNames struct {
	r     *obfRand
	names map[string]string
}

func newGeneratedNames(r *obfRand) *generatedNames {
	return &generatedNames{r: r, names: make(map[string]string)}
}

func (n *generatedNames) name(original string) string {
	if name, ok := n.names[original]; ok {
		return name
	}
	name := n.r.nameFunc(n.r.rnd, "literalLocal"+original)
	n.names[original] = name
	return name
}

func (n *generatedNames) ident(original string) *ast.Ident {
	return ast.NewIdent(n.name(original))
}

func (r *obfRand) nextLiftedFuncName(base string) string {
	name := r.nameFunc(r.rnd, fmt.Sprintf("%s%d", base, r.liftedFuncSeq))
	r.liftedFuncSeq++
	return name
}

// handleCompositeLiteral checks if the input node is []byte or [...]byte and
// calls the appropriate obfuscation method, returning a new node that should
// be used to replace it.
//
// If the input node cannot be obfuscated nil is returned.
func handleCompositeLiteral(or *obfRand, isPointer bool, node *ast.CompositeLit, info *types.Info) ast.Node {
	if len(node.Elts) < MinSize {
		return nil
	}

	byteType := types.Universe.Lookup("byte").Type()

	var arrayLen int64
	switch y := info.TypeOf(node.Type).(type) {
	case *types.Array:
		if y.Elem() != byteType {
			return nil
		}

		arrayLen = y.Len()

	case *types.Slice:
		if y.Elem() != byteType {
			return nil
		}

	default:
		return nil
	}

	data := make([]byte, 0, len(node.Elts))

	for _, el := range node.Elts {
		elType := info.Types[el]

		if elType.Value == nil || elType.Value.Kind() != constant.Int {
			return nil
		}

		value, ok := constant.Uint64Val(elType.Value)
		if !ok {
			panic(fmt.Sprintf("cannot parse byte value: %v", elType.Value))
		}

		data = append(data, byte(value))
	}

	return withPos(obfuscateBytes(or, isPointer, data, arrayLen), node.Pos())
}

// withPos sets any token.Pos fields under node which affect printing to pos.
// Note that we can't set all token.Pos fields, since some affect the semantics.
//
// This function is useful so that go/printer doesn't try to estimate position
// offsets, which can end up in printing comment directives too early.
//
// We don't set any "end" or middle positions, because they seem irrelevant.
func withPos(node ast.Node, pos token.Pos) ast.Node {
	for node := range ast.Preorder(node) {
		switch node := node.(type) {
		case *ast.BasicLit:
			node.ValuePos = pos
		case *ast.Ident:
			node.NamePos = pos
		case *ast.CompositeLit:
			node.Lbrace = pos
			node.Rbrace = pos
		case *ast.ArrayType:
			node.Lbrack = pos
		case *ast.FuncType:
			node.Func = pos
		case *ast.BinaryExpr:
			node.OpPos = pos
		case *ast.StarExpr:
			node.Star = pos
		case *ast.CallExpr:
			node.Lparen = pos
			node.Rparen = pos

		case *ast.GenDecl:
			node.TokPos = pos
		case *ast.ReturnStmt:
			node.Return = pos
		case *ast.ForStmt:
			node.For = pos
		case *ast.RangeStmt:
			node.For = pos
		case *ast.BranchStmt:
			node.TokPos = pos
		}
	}
	return node
}

func obfuscateString(or *obfRand, data string) *ast.CallExpr {
	if call := or.stringCalls[data]; call != nil {
		return or.proxyDispatcher.cloneStringCall(call).(*ast.CallExpr)
	}
	call := or.cipherCall(true, []byte(data))
	if or.stringCalls != nil {
		or.stringCalls[data] = call
		return or.proxyDispatcher.cloneStringCall(call).(*ast.CallExpr)
	}
	return call
}

// byteHelperKey identifies a helper converting a decoded slice into the form
// of the original byte literal.
type byteHelperKey struct {
	isPointer bool
	arrayLen  int64
}

// decoderFuncType is the type of a hidden decoder entry, which takes the
// ciphertext, the owner's key half and the bounds of the plaintext.
func decoderFuncType(result ast.Expr) *ast.FuncType {
	params := &ast.FieldList{}
	for _, typ := range []string{"string", "uint64", "uint64", "int", "int"} {
		params.List = append(params.List, &ast.Field{Type: ast.NewIdent(typ)})
	}
	return &ast.FuncType{Params: params, Results: &ast.FieldList{List: []*ast.Field{{Type: result}}}}
}

// cipherCall encrypts plain under the current owner's key and returns a call
// decoding it, to a string if str is set and to a fresh byte slice otherwise.
// Both the decoder and the owner's key half are only reachable through the
// owner's proxy tree.
func (r *obfRand) cipherCall(str bool, plain []byte) *ast.CallExpr {
	if r.cipher == nil {
		v := newCipherVariant(r.rnd)
		r.cipher = &v
		r.bytesDecoder = r.nextLiftedFuncName("literalDecoder")
		r.liftedFuncs = append(r.liftedFuncs, v.emitDecoder(r.bytesDecoder, newGeneratedNames(r)))

		r.stringDecoder = r.nextLiftedFuncName("literalString")
		names := newGeneratedNames(r)
		args := []ast.Expr{names.ident("ct"), names.ident("o0"), names.ident("o1"), names.ident("low"), names.ident("high")}
		r.liftedFuncs = append(r.liftedFuncs, &ast.FuncDecl{
			Name: ast.NewIdent(r.stringDecoder),
			Type: &ast.FuncType{
				Params: &ast.FieldList{List: []*ast.Field{
					ah.Field(ast.NewIdent("string"), names.ident("ct")),
					ah.Field(ast.NewIdent("uint64"), names.ident("o0"), names.ident("o1")),
					ah.Field(ast.NewIdent("int"), names.ident("low"), names.ident("high")),
				}},
				Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("string")}}},
			},
			Body: ah.BlockStmt(ah.ReturnStmt(ah.CallExprByName("string", ah.CallExpr(ast.NewIdent(r.bytesDecoder), args...)))),
		})
	}
	d := r.proxyDispatcher
	if d.ownerKey == nil {
		key := newOwnerKey(r.rnd)
		d.ownerKey = &key
		// Halves stored side by side would give away the whole key to a
		// scan of neighboring words, so each gets its own allocation.
		for i, half := range key {
			d.ownerKeyPaths[i] = d.hideApart(ah.UintLit(half), ast.NewIdent("uint64"))
		}
	}
	entry, decoder, result := &d.bytesEntry, r.bytesDecoder, ast.Expr(ah.ByteSliceType())
	if str {
		entry, decoder, result = &d.stringEntry, r.stringDecoder, ast.NewIdent("string")
	}
	if *entry == nil {
		*entry = d.HideValue(ast.NewIdent(decoder), decoderFuncType(result))
	}
	ct, low, high := r.cipher.encode(r.rnd, plain, *d.ownerKey)
	return ah.CallExpr(d.clonePath(*entry), ah.StringLit(ct),
		d.clonePath(d.ownerKeyPaths[0]), d.clonePath(d.ownerKeyPaths[1]),
		ah.IntLit(low), ah.IntLit(high))
}

// byteHelper returns a lifted function converting a decoded slice into a
// slice pointer, an array, or an array pointer. Helpers are top-level, so a
// locally shadowed builtin such as copy cannot reach them.
func (r *obfRand) byteHelper(isPointer bool, arrayLen int64) string {
	key := byteHelperKey{isPointer: isPointer, arrayLen: arrayLen}
	if name, ok := r.byteHelpers[key]; ok {
		return name
	}
	name := r.nextLiftedFuncName("literalBytes")
	names := newGeneratedNames(r)
	results := &ast.FieldList{}
	var body *ast.BlockStmt
	copyStmt := func() ast.Stmt {
		return ah.ExprStmt(ah.CallExprByName("copy", &ast.SliceExpr{X: names.ident("array")}, names.ident("slice")))
	}
	switch {
	case arrayLen == 0: // func(slice []byte) *[]byte
		results.List = []*ast.Field{{Type: ah.StarExpr(ah.ByteSliceType())}}
		body = ah.BlockStmt(ah.ReturnStmt(ah.UnaryExpr(token.AND, names.ident("slice"))))
	case !isPointer: // func(slice []byte) (array [N]byte)
		results.List = []*ast.Field{ah.Field(ah.ByteArrayType(arrayLen), names.ident("array"))}
		body = ah.BlockStmt(copyStmt(), &ast.ReturnStmt{})
	default: // func(slice []byte) *[N]byte
		results.List = []*ast.Field{{Type: ah.StarExpr(ah.ByteArrayType(arrayLen))}}
		body = ah.BlockStmt(
			ah.AssignDefineStmt(names.ident("array"), ah.CallExprByName("new", ah.ByteArrayType(arrayLen))),
			copyStmt(),
			ah.ReturnStmt(names.ident("array")),
		)
	}
	r.liftedFuncs = append(r.liftedFuncs, &ast.FuncDecl{
		Name: ast.NewIdent(name),
		Type: &ast.FuncType{
			Params:  &ast.FieldList{List: []*ast.Field{ah.Field(ah.ByteSliceType(), names.ident("slice"))}},
			Results: results,
		},
		Body: body,
	})
	if r.byteHelpers == nil {
		r.byteHelpers = make(map[byteHelperKey]string)
	}
	r.byteHelpers[key] = name
	return name
}

// Each use needs independent positions; only the hidden values and decoder are
// shared, not mutable AST nodes or the result of running the decoder.
func (d *proxyDispatcher) cloneStringCall(expr ast.Expr) ast.Expr {
	switch expr := expr.(type) {
	case *ast.CallExpr:
		args := make([]ast.Expr, len(expr.Args))
		for i, arg := range expr.Args {
			args[i] = d.cloneStringCall(arg)
		}
		return &ast.CallExpr{Fun: d.cloneStringCall(expr.Fun), Args: args}
	case *ast.SelectorExpr:
		return d.clonePath(expr)
	case *ast.Ident:
		return ast.NewIdent(expr.Name)
	case *ast.BasicLit:
		return &ast.BasicLit{Kind: expr.Kind, Value: expr.Value}
	default:
		panic(fmt.Sprintf("unsupported string decoder expression %T", expr))
	}
}

// obfuscateBytes returns a call decoding data to a fresh slice, converted to
// an array when arrayLen is non-zero and to a pointer when isPointer is set.
func obfuscateBytes(or *obfRand, isPointer bool, data []byte, arrayLen int64) *ast.CallExpr {
	call := or.cipherCall(false, data)
	if !isPointer && arrayLen == 0 {
		return call
	}
	return ah.CallExprByName(or.byteHelper(isPointer, arrayLen), call)
}

// isEmbeddedPlaceholder reports whether expr is the initializer that the embed
// transform installed for a //go:embed variable. Such a variable is uninitialized
// in the source, which is the case where cmd/link applies a -X assignment, so the
// placeholder must not be mistaken for a non-constant initializer.
func isEmbeddedPlaceholder(expr ast.Expr, embeds map[ast.Expr]EmbeddedValue) bool {
	_, ok := embeds[expr]
	return ok
}
