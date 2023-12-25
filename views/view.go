package views

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

var TemplatesDir = "templates"

//go:embed templates/* templates/layout/* templates/auth/* templates/profile/*
var templates embed.FS

var StandardFunctions = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
}

type View struct {
	Template *template.Template
	Layout   string
}

func NewView(layout string, files ...string) *View {
	tmplFiles := []string{
		"templates/layout/layout.gohtml",
		"templates/layout/shell.gohtml",
		"templates/layout/partial.gohtml",
	}
	tmplFiles = append(tmplFiles, viewFiles(files)...)
	tmpl, e := template.New("").Funcs(StandardFunctions).ParseFS(templates, tmplFiles...)
	if e != nil {
		panic(e)
	}
	return &View{Template: tmpl, Layout: layout}
}

type ViewData struct {
	Data  map[string]interface{}
	Flash string
}

func (v *View) Render(w http.ResponseWriter, _ *http.Request, data map[string]interface{}) {
	vd := ViewData{Data: data}
	var rb bytes.Buffer
	e := v.Template.ExecuteTemplate(&rb, v.Layout, vd)
	if e != nil {
		fmt.Printf("Error rendering template: %v\n", e)
		http.Error(w,
			fmt.Sprintf("Error rendering template: %v", e),
			http.StatusInternalServerError)
	} else {
		_, _ = w.Write(rb.Bytes())
	}
}

func ViewHandler(view *View) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view.Render(w, r, nil)
	}
}

func RedirectHandler(view *View) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		hxRequest := r.URL.Query().Get("hxr")
		hxAuthenticated := r.URL.Query().Get("hxa")
		view.Render(w, r, map[string]interface{}{
			"Target":          target,
			"HxRequest":       hxRequest,
			"HxAuthenticated": hxAuthenticated,
		})
	}
}

func viewFiles(files []string) []string {
	var paths []string
	for _, file := range files {
		paths = append(paths, filepath.Join(TemplatesDir, file))
	}
	return paths
}
