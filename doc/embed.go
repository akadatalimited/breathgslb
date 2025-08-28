package doc

import _ "embed"

//go:embed openapi.yaml
var OpenAPIYAML []byte

//go:embed swagger.html
var SwaggerHTML []byte
