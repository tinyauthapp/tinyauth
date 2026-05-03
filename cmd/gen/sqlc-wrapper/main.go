// gen/sqlc-wrapper generates store.go wrapper files for each sqlc driver package under
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

func main() {
	driverPkg := flag.String("pkg", "", "import path of the driver package")
	out := flag.String("out", "store.go", "output filename relative to driver package directory")
	flag.Parse()

	if *driverPkg == "" {
		log.Fatal("-pkg is required")
	}

	// Resolve the driver package directory so we can overlay the output file
	// with a valid stub. This prevents a stale store.go from poisoning the
	// type-checker and producing cryptic "undefined" errors.
	driverDir, err := pkgDir(*driverPkg)
	if err != nil {
		log.Fatalf("resolve driver dir: %v", err)
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
	pkgs, err := packages.Load(cfg, *driverPkg)
	if err != nil {
		log.Fatalf("load %s: %v", *driverPkg, err)
	}
	if len(pkgs) != 1 {
		log.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	pkg := pkgs[0]
	if len(pkg.Errors) > 0 {
		for _, e := range pkg.Errors {
			log.Printf("package error: %v", e)
		}
		log.Fatal("package has errors")
	}

	repoPkg := parentPkg(*driverPkg)

	// Load the parent (repository) package so we can validate struct shapes.
	repoPkgs, err := packages.Load(cfg, repoPkg)
	if err != nil {
		log.Fatalf("load repo pkg %s: %v", repoPkg, err)
	}
	if len(repoPkgs) != 1 || len(repoPkgs[0].Errors) > 0 {
		log.Fatalf("could not load repo package %s cleanly", repoPkg)
	}
	if err := validateStructShapes(pkg.Types, repoPkgs[0].Types); err != nil {
		log.Fatalf("struct shape mismatch: %v", err)
	}

	// Check *Queries covers every method in repository.Store before generating.
	if err := validateStoreCoverage(pkg.Types, repoPkgs[0].Types); err != nil {
		log.Fatalf("%v", err)
	}

	methods, err := collectMethods(pkg.Types)
	if err != nil {
		log.Fatal(err)
	}

	models, _ := collectTypes(pkg.Types)

	data := tmplData{
		PkgName:    pkg.Name,
		RepoPkg:    repoPkg,
		ModelTypes: models,
		Methods:    renderMethods(methods),
	}

	src, err := render(data)
	if err != nil {
		log.Fatalf("render: %v", err)
	}

	if err := os.WriteFile(outPath, src, 0644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	fmt.Printf("wrote %s\n", outPath)
}

func parentPkg(imp string) string {
	parts := strings.Split(imp, "/")
	return strings.Join(parts[:len(parts)-1], "/")
}

// pkgDir returns the on-disk directory for an import path using `go list`.
func pkgDir(importPath string) (string, error) {
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", importPath).Output()
	if err != nil {
		return "", fmt.Errorf("go list %s: %w", importPath, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// validateStoreCoverage checks that every method declared in repository.Store
// exists on *Queries in the driver package. Missing methods are reported by
// name so the developer knows exactly which SQL queries need to be added.
func validateStoreCoverage(driverPkg, repoPkg *types.Package) error {
	// Collect *Queries method names.
	queriesObj := driverPkg.Scope().Lookup("Queries")
	if queriesObj == nil {
		return fmt.Errorf("Queries type not found in driver package")
	}
	queriesNamed := queriesObj.Type().(*types.Named)
	queriesMS := types.NewMethodSet(types.NewPointer(queriesNamed))
	queriesMethods := make(map[string]bool)
	for m := range queriesMS.Methods() {
		queriesMethods[m.Obj().Name()] = true
	}

	// Collect repository.Store interface methods.
	storeObj := repoPkg.Scope().Lookup("Store")
	if storeObj == nil {
		return fmt.Errorf("Store type not found in repository package")
	}
	storeIface, ok := storeObj.Type().Underlying().(*types.Interface)
	if !ok {
		return fmt.Errorf("repository.Store is not an interface")
	}

	var missing []string
	for i := range storeIface.NumMethods() {
		name := storeIface.Method(i).Name()
		if !queriesMethods[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf(
			"driver *Queries is missing %d method(s) required by repository.Store:\n  - %s\n\nRun sqlc generate to regenerate query methods, or add the missing SQL queries.",
			len(missing), strings.Join(missing, "\n  - "),
		)
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
	pi := paramInfo{Name: name}
	pi.TypeStr = localName(t, driverPath)
	pi.RepoType = repoName(t, driverPath)
	return pi
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

func collectTypes(pkg *types.Package) (models []string, params []string) {
	for _, name := range pkg.Scope().Names() {
		obj := pkg.Scope().Lookup(name)
		if obj == nil {
			continue
		}
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, ok := named.Underlying().(*types.Struct); !ok {
			continue
		}
		switch name {
		case "Queries", "DBTX", "Store":
			continue
		}
		if strings.HasSuffix(name, "Params") {
			params = append(params, name)
		} else {
			models = append(models, name)
		}
	}
	return
}

// validateStructShapes checks that every model/params struct in the driver
// package has fields that exactly match the corresponding type in the repo
// (parent) package. This catches drift between sqlc-generated types and the
// canonical repository types before a broken cast reaches the compiler.
func validateStructShapes(driverPkg, repoPkg *types.Package) error {
	var errs []string
	for _, name := range driverPkg.Scope().Names() {
		obj := driverPkg.Scope().Lookup(name)
		if obj == nil {
			continue
		}
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		driverStruct, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		switch name {
		case "Queries", "DBTX", "Store":
			continue
		}

		repoObj := repoPkg.Scope().Lookup(name)
		if repoObj == nil {
			// Driver has a type not in repo — that's fine (e.g. internal helpers).
			continue
		}
		repoNamed, ok := repoObj.Type().(*types.Named)
		if !ok {
			continue
		}
		repoStruct, ok := repoNamed.Underlying().(*types.Struct)
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: repo type is not a struct", name))
			continue
		}

		if err := compareStructs(name, driverStruct, repoStruct); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
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

// converterFn: "Session" -> "sessionToRepo"
func converterFn(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = []rune(strings.ToLower(string(r[0])))[0]
	return string(r) + "ToRepo"
}

// renderedMethod is the pre-built method body passed to the template.
type renderedMethod struct {
	Signature string
	Body      string
}

// renderMethods converts []methodInfo into fully pre-rendered signature+body strings.
func renderMethods(methods []methodInfo) []renderedMethod {
	var out []renderedMethod
	for _, m := range methods {
		out = append(out, renderedMethod{
			Signature: buildSig(m),
			Body:      buildBody(m),
		})
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
	var args []string
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

func buildBody(m methodInfo) string {
	call := "s.q." + m.Name + "(" + callArgs(m) + ")"

	// no repo-typed result → direct return
	if len(m.Results) == 0 || m.Results[0].RepoType == "" {
		return "\treturn mapErr(" + call + ")\n"
	}

	r := m.Results[0]
	if r.IsSlice {
		return fmt.Sprintf(
			"\trows, err := %s\n\tif err != nil {\n\t\treturn nil, mapErr(err)\n\t}\n\tout := make([]%s, len(rows))\n\tfor i, row := range rows {\n\t\tout[i] = %s(row)\n\t}\n\treturn out, nil\n",
			call, r.RepoType, converterFn(r.TypeStr),
		)
	}
	return fmt.Sprintf(
		"\tr, err := %s\n\tif err != nil {\n\t\treturn %s{}, mapErr(err)\n\t}\n\treturn %s(r), nil\n",
		call, r.RepoType, converterFn(r.TypeStr),
	)
}

type tmplData struct {
	PkgName    string
	RepoPkg    string
	ModelTypes []string
	Methods    []renderedMethod
}

const storeSrc = `// Code generated by cmd/gen/sqlc-wrapper. DO NOT EDIT.
package {{.PkgName}}

import (
	"context"
	"database/sql"
	"errors"

	"{{.RepoPkg}}"
)

// Store wraps *Queries and implements repository.Store.
type Store struct {
	q *Queries
}

// NewStore wraps a *Queries to satisfy repository.Store.
func NewStore(q *Queries) repository.Store {
	return &Store{q: q}
}

var errMap = []struct {
	from error
	to   error
}{
	{sql.ErrNoRows, repository.ErrNotFound},
}

func mapErr(err error) error {
	for _, e := range errMap {
		if errors.Is(err, e.from) {
			return e.to
		}
	}
	return err
}

{{range .ModelTypes -}}
func {{converterFn .}}(v {{.}}) repository.{{.}} {
	return repository.{{.}}(v)
}
{{end -}}
{{range .Methods}}{{.Signature}} {
{{.Body}}}

{{end}}`

func render(data tmplData) ([]byte, error) {
	t, err := template.New("store").Funcs(template.FuncMap{
		"converterFn": converterFn,
	}).Parse(storeSrc)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return buf.Bytes(), fmt.Errorf("format source: %w\nraw:\n%s", err, buf.String())
	}
	return formatted, nil
}
