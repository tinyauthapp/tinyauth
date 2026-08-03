// gen/sqlc_wrapper generates store.go wrapper files for each sqlc driver package under
// internal/repository/<driver>/. Run via:
//
//	go generate ./internal/repository/...
//
// The generator introspects *Queries methods and the model/params types in the
// driver package, then emits a store.go that wraps *Queries so it satisfies
// repository.Store using the canonical shared types in the parent package.
// This generator is specific to sqlc-generated drivers. Non-sqlc drivers should
// implement repository.Store directly by hand.
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"go/format"
	"go/types"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"golang.org/x/tools/go/packages"
)

//go:embed store.tmpl
var storeSrc string

func main() {
	fmt.Println("sqlc_wrapper: generating store.go files for sqlc driver packages...")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	driverPkg := flag.String("pkg", "", "import path of the driver package")
	out := flag.String("out", "store.go", "output filename relative to driver package directory")
	flag.Parse()

	if *driverPkg == "" {
		return fmt.Errorf("-pkg is required")
	}

	// Resolve the driver package directory so we can overlay the output file
	// with a valid stub. This prevents a stale store.go from poisoning the
	// type-checker and producing cryptic "undefined" errors.
	driverDir, err := pkgDir(*driverPkg)
	if err != nil {
		return fmt.Errorf("resolve driver dir: %w", err)
	}

	outPath := filepath.Join(driverDir, *out)
	if filepath.IsAbs(*out) {
		outPath = *out
	}

	// Stub replaces the output file during load so stale generated code is ignored.
	stub := []byte("package " + filepath.Base(driverDir) + "\n")
	cfg := &packages.Config{
		Mode:    packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedImports,
		Overlay: map[string][]byte{outPath: stub},
	}

	driverTypePkg, err := loadOnePkg(cfg, *driverPkg)
	if err != nil {
		return fmt.Errorf("load driver package: %w", err)
	}

	repoPkgPath := parentPkg(*driverPkg)
	repoTypePkg, err := loadOnePkg(cfg, repoPkgPath)
	if err != nil {
		return fmt.Errorf("load repo package: %w", err)
	}

	if err := validateStructShapes(driverTypePkg, repoTypePkg); err != nil {
		return fmt.Errorf("struct shape mismatch: %w", err)
	}
	if err := validateStoreCoverage(driverTypePkg, repoTypePkg); err != nil {
		return err
	}

	methods, err := collectMethods(driverTypePkg)
	if err != nil {
		return err
	}

	src, err := render(tmplData{
		PkgName: driverTypePkg.Name(),
		RepoPkg: repoPkgPath,
		Methods: renderMethods(methods),
	})
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}

	if err := os.WriteFile(outPath, src, 0644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("wrote %s\n", outPath)
	return nil
}

// loadOnePkg loads a single package via cfg and returns its *types.Package,
// or an error if the package fails to load or has type errors.
func loadOnePkg(cfg *packages.Config, importPath string) (*types.Package, error) {
	pkgs, err := packages.Load(cfg, importPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", importPath, err)
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("expected 1 package for %s, got %d", importPath, len(pkgs))
	}
	pkg := pkgs[0]
	if len(pkg.Errors) > 0 {
		msgs := make([]string, len(pkg.Errors))
		for i, e := range pkg.Errors {
			msgs[i] = e.Error()
		}
		return nil, fmt.Errorf("package %s has errors:\n  %s", importPath, strings.Join(msgs, "\n  "))
	}
	return pkg.Types, nil
}

// parentPkg returns the parent import path (everything before the last /).
// Panics if imp contains no slash — callers are expected to pass driver sub-packages.
func parentPkg(imp string) string {
	i := strings.LastIndex(imp, "/")
	if i < 0 {
		panic(fmt.Sprintf("parentPkg: import path %q has no parent", imp))
	}
	return imp[:i]
}

// pkgDir returns the on-disk directory for an import path using `go list`.
func pkgDir(importPath string) (string, error) {
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", importPath).Output()
	if err != nil {
		return "", fmt.Errorf("go list %s: %w", importPath, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// scopeStructs returns all named struct types in pkg, excluding the internal
// sqlc types Queries, DBTX, and Store. Names are returned in sorted order.
func scopeStructs(pkg *types.Package) (names []string, byName map[string]*types.Struct) {
	byName = make(map[string]*types.Struct)
	for _, name := range pkg.Scope().Names() { // Names() is already sorted
		switch name {
		case "Queries", "DBTX", "Store":
			continue
		}
		obj, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}
		s, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		names = append(names, name)
		byName[name] = s
	}
	return
}

// validateStoreCoverage checks that every method declared in repository.Store
// exists on *Queries in the driver package. Missing methods are reported by
// name so the developer knows exactly which SQL queries need to be added.
func validateStoreCoverage(driverPkg, repoPkg *types.Package) error {
	queriesObj := driverPkg.Scope().Lookup("Queries")
	if queriesObj == nil {
		return fmt.Errorf("queries type not found in driver package")
	}
	queriesNamed := queriesObj.Type().(*types.Named)
	queriesMS := types.NewMethodSet(types.NewPointer(queriesNamed))
	queriesMethods := make(map[string]bool)
	for m := range queriesMS.Methods() {
		queriesMethods[m.Obj().Name()] = true
	}

	storeObj := repoPkg.Scope().Lookup("Store")
	if storeObj == nil {
		return fmt.Errorf("store type not found in repository package")
	}
	storeIface, ok := storeObj.Type().Underlying().(*types.Interface)
	if !ok {
		return fmt.Errorf("repository.Store is not an interface")
	}

	var missing []string
	for method := range storeIface.Methods() {
		if name := method.Name(); !queriesMethods[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf(
			"driver *Queries is missing %d method(s) required by repository.Store:\n  - %s\n\nRun sqlc generate to regenerate query methods, or add the missing SQL queries",
			len(missing), strings.Join(missing, "\n  - "),
		)
	}
	return nil
}

// validateStructShapes checks that every model/params struct in the driver
// package has fields that exactly match the corresponding type in the repo
// (parent) package. This catches drift between sqlc-generated types and the
// canonical repository types before a broken cast reaches the compiler.
func validateStructShapes(driverPkg, repoPkg *types.Package) error {
	_, repoStructs := scopeStructs(repoPkg)
	driverNames, driverStructs := scopeStructs(driverPkg)

	var errs []string
	for _, name := range driverNames {
		repoStruct, ok := repoStructs[name]
		if !ok {
			// Driver has a type not in repo — fine (e.g. internal helpers).
			continue
		}
		if err := compareStructs(name, driverStructs[name], repoStruct); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("%s", strings.Join(errs, "\n  "))
	}
	return nil
}

func compareStructs(name string, driver, repo *types.Struct) error {
	if driver.NumFields() != repo.NumFields() {
		return fmt.Errorf("%s: field count mismatch (driver=%d, repo=%d)",
			name, driver.NumFields(), repo.NumFields())
	}
	for i := range driver.NumFields() {
		df := driver.Field(i)
		rf := repo.Field(i)
		if df.Name() != rf.Name() {
			return fmt.Errorf("%s: field %d name mismatch (driver=%q, repo=%q)",
				name, i, df.Name(), rf.Name())
		}
		if !types.Identical(df.Type(), rf.Type()) {
			return fmt.Errorf("%s.%s: type mismatch (driver=%s, repo=%s)",
				name, df.Name(), df.Type(), rf.Type())
		}
	}
	return nil
}

type methodInfo struct {
	Name    string
	Params  []paramInfo
	Results []resultInfo
}

type paramInfo struct {
	Name     string
	TypeStr  string // local (unqualified) type name
	RepoType string // "repository.X" if this is a driver model/params type; else ""
}

type resultInfo struct {
	TypeStr  string
	IsSlice  bool
	RepoType string // "repository.X" if driver type; else ""
}

func collectMethods(pkg *types.Package) ([]methodInfo, error) {
	obj := pkg.Scope().Lookup("Queries")
	if obj == nil {
		return nil, fmt.Errorf("queries type not found in %s", pkg.Path())
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return nil, fmt.Errorf("queries is not a named type")
	}
	ms := types.NewMethodSet(types.NewPointer(named))

	var out []methodInfo
	for method := range ms.Methods() {
		fn, ok := method.Obj().(*types.Func)
		if !ok || fn.Name() == "WithTx" {
			continue
		}
		sig := fn.Type().(*types.Signature)
		mi := methodInfo{Name: fn.Name()}

		// params: skip receiver + first (context.Context)
		for i := 1; i < sig.Params().Len(); i++ {
			p := sig.Params().At(i)
			mi.Params = append(mi.Params, makeParam(p.Name(), p.Type(), pkg.Path()))
		}
		// results: skip error
		for r := range sig.Results().Variables() {
			if r.Type().String() == "error" {
				continue
			}
			mi.Results = append(mi.Results, makeResult(r.Type(), pkg.Path()))
		}
		out = append(out, mi)
	}
	return out, nil
}

func makeParam(name string, t types.Type, driverPath string) paramInfo {
	return paramInfo{
		Name:     name,
		TypeStr:  localName(t, driverPath),
		RepoType: repoName(t, driverPath),
	}
}

func makeResult(t types.Type, driverPath string) resultInfo {
	ri := resultInfo{}
	if sl, ok := t.(*types.Slice); ok {
		ri.IsSlice = true
		t = sl.Elem()
	}
	ri.TypeStr = localName(t, driverPath)
	ri.RepoType = repoName(t, driverPath)
	return ri
}

func localName(t types.Type, driverPath string) string {
	named, ok := t.(*types.Named)
	if !ok {
		return types.TypeString(t, nil)
	}
	if named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == driverPath {
		return named.Obj().Name()
	}
	return types.TypeString(t, func(p *types.Package) string { return p.Name() })
}

func repoName(t types.Type, driverPath string) string {
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	if named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == driverPath {
		return "repository." + named.Obj().Name()
	}
	return ""
}

// renderedMethod holds pre-built signature and body strings passed to the template.
type renderedMethod struct {
	Signature string
	Body      string
}

func renderMethods(methods []methodInfo) []renderedMethod {
	out := make([]renderedMethod, len(methods))
	for i, m := range methods {
		out[i] = renderedMethod{
			Signature: buildSig(m),
			Body:      buildBody(m),
		}
	}
	return out
}

func buildSig(m methodInfo) string {
	var sb strings.Builder
	sb.WriteString("func (s *Store) ")
	sb.WriteString(m.Name)
	sb.WriteString("(ctx context.Context")
	for _, p := range m.Params {
		sb.WriteString(", ")
		sb.WriteString(p.Name)
		sb.WriteString(" ")
		if p.RepoType != "" {
			sb.WriteString(p.RepoType)
		} else {
			sb.WriteString(p.TypeStr)
		}
	}
	sb.WriteString(") (")
	for _, r := range m.Results {
		if r.IsSlice {
			sb.WriteString("[]")
		}
		if r.RepoType != "" {
			sb.WriteString(r.RepoType)
		} else {
			sb.WriteString(r.TypeStr)
		}
		sb.WriteString(", ")
	}
	sb.WriteString("error)")
	return sb.String()
}

func callArgs(m methodInfo) string {
	args := make([]string, 0, len(m.Params))
	for _, p := range m.Params {
		if p.RepoType != "" {
			// convert repo type → driver type: DriverType(arg)
			args = append(args, p.TypeStr+"("+p.Name+")")
		} else {
			args = append(args, p.Name)
		}
	}
	if len(args) == 0 {
		return "ctx"
	}
	return "ctx, " + strings.Join(args, ", ")
}

var bodyTmpl = template.Must(template.New("store").Parse(storeSrc))

type bodyData struct {
	Call     string
	RepoType string
}

func buildBody(m methodInfo) string {
	call := "s.q." + m.Name + "(" + callArgs(m) + ")"

	var (
		name string
		data bodyData
	)

	switch {
	case len(m.Results) == 0 || m.Results[0].RepoType == "":
		name = "void"
		data = bodyData{Call: call}
	case m.Results[0].IsSlice:
		name = "slice"
		data = bodyData{Call: call, RepoType: m.Results[0].RepoType}
	default:
		name = "scalar"
		data = bodyData{Call: call, RepoType: m.Results[0].RepoType}
	}

	var buf bytes.Buffer
	if err := bodyTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		panic(fmt.Sprintf("buildBody %s: %v", name, err))
	}
	return buf.String()
}

type tmplData struct {
	PkgName string
	RepoPkg string
	Methods []renderedMethod
}

func render(data tmplData) ([]byte, error) {
	var buf bytes.Buffer
	if err := bodyTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return buf.Bytes(), fmt.Errorf("format source: %w\nraw:\n%s", err, buf.String())
	}
	return formatted, nil
}
