// Package openapi embeds the console API contract so the server validates
// requests against the same document the console's types are generated from.
package openapi

import _ "embed"

// Console is the OpenAPI 3.1 document for the browser-facing API.
//
//go:embed console.yaml
var Console []byte
