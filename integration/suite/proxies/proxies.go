package proxies

import (
	_ "embed"
	"html/template"
)

// Bundle the templates

//go:embed caddy.yaml.tmpl
var caddyTemplateSource string

//go:embed envoy.yaml.tmpl
var envoyTemplateSource string

//go:embed nginx.yaml.tmpl
var nginxTemplateSource string

//go:embed traefik.yaml.tmpl
var traefikTemplateSource string

// Compile them and export them

var CaddyTemplate = template.Must(template.New("caddy").Parse(caddyTemplateSource))
var EnvoyTemplate = template.Must(template.New("envoy").Parse(envoyTemplateSource))
var NginxTemplate = template.Must(template.New("nginx").Parse(nginxTemplateSource))
var TraefikTemplate = template.Must(template.New("traefik").Parse(traefikTemplateSource))
