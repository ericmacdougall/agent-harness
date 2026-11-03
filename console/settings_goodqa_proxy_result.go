package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
)

// Check the negotiated MCP result envelope and known content fields, without
// interpreting a tool's arbitrary structured data or introducing JSON Schema.
func goodqaValidateCallResult(raw json.RawMessage, protocol string) error {
	root, ok := goodqaResultObject(raw)
	if !ok {
		return errors.New("tool result must be an object")
	}
	content, exists := root["content"]
	if !exists || len(bytes.TrimSpace(content)) == 0 || bytes.TrimSpace(content)[0] != '[' {
		return errors.New("tool result requires content array")
	}
	var blocks []json.RawMessage
	if json.Unmarshal(content, &blocks) != nil {
		return errors.New("invalid content array")
	}
	if raw, exists := root["isError"]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) && !bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return errors.New("isError must be boolean")
	}
	if !goodqaObjectField(root, "structuredContent") || !goodqaObjectField(root, "_meta") {
		return errors.New("structured content and metadata must be objects")
	}
	if protocol == "" {
		protocol = "2025-06-18"
	}
	for _, raw := range blocks {
		block, ok := goodqaResultObject(raw)
		if !ok || !goodqaStringField(block, "type", true) || !goodqaContentMetadata(block) {
			return errors.New("invalid tool content block")
		}
		var kind string
		_ = json.Unmarshal(block["type"], &kind)
		switch kind {
		case "text":
			if !goodqaStringField(block, "text", true) {
				return errors.New("text content requires text string")
			}
		case "image", "audio":
			if kind == "audio" && protocol == "2024-11-05" {
				return errors.New("audio not supported by negotiated version")
			}
			if !goodqaStringField(block, "data", true) || !goodqaStringField(block, "mimeType", true) {
				return errors.New("media content requires data and mimeType strings")
			}
		case "resource_link":
			if protocol != "2025-06-18" || !goodqaStringField(block, "name", true) || !goodqaURIField(block) || !goodqaStringField(block, "description", false) || !goodqaStringField(block, "mimeType", false) || !goodqaStringField(block, "title", false) {
				return errors.New("invalid resource link for negotiated version")
			}
			if size, present := block["size"]; present {
				if _, e := strconv.ParseFloat(string(bytes.TrimSpace(size)), 64); e != nil {
					return errors.New("resource size must be numeric")
				}
			}
		case "resource":
			resource, ok := goodqaResultObject(block["resource"])
			if !ok || !goodqaURIField(resource) || !goodqaStringField(resource, "mimeType", false) || !goodqaObjectField(resource, "_meta") {
				return errors.New("embedded resource requires URI and content")
			}
			_, hasText := resource["text"]
			_, hasBlob := resource["blob"]
			if (!hasText && !hasBlob) || !goodqaStringField(resource, "text", false) || !goodqaStringField(resource, "blob", false) {
				return errors.New("embedded resource text/blob must be a string")
			}
		default:
			return errors.New("unsupported tool content type")
		}
	}
	return nil
}
func goodqaResultObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(trimmed, &object) != nil || object == nil {
		return nil, false
	}
	return object, true
}
func goodqaStringField(object map[string]json.RawMessage, key string, required bool) bool {
	raw, exists := object[key]
	if !exists {
		return !required
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return false
	}
	var value string
	return json.Unmarshal(trimmed, &value) == nil
}
func goodqaObjectField(object map[string]json.RawMessage, key string) bool {
	raw, exists := object[key]
	if !exists {
		return true
	}
	_, ok := goodqaResultObject(raw)
	return ok
}
func goodqaURIField(object map[string]json.RawMessage) bool {
	if !goodqaStringField(object, "uri", true) {
		return false
	}
	var uri string
	_ = json.Unmarshal(object["uri"], &uri)
	parsed, e := url.Parse(uri)
	return e == nil && parsed.Scheme != ""
}
func goodqaContentMetadata(block map[string]json.RawMessage) bool {
	if !goodqaObjectField(block, "_meta") {
		return false
	}
	raw, exists := block["annotations"]
	if !exists {
		return true
	}
	annotations, ok := goodqaResultObject(raw)
	if !ok {
		return false
	}
	if raw, exists := annotations["audience"]; exists {
		if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' {
			return false
		}
		var roles []string
		if json.Unmarshal(raw, &roles) != nil {
			return false
		}
		for _, role := range roles {
			if !oneOf(role, "user", "assistant") {
				return false
			}
		}
	}
	if raw, exists := annotations["priority"]; exists {
		priority, e := strconv.ParseFloat(string(bytes.TrimSpace(raw)), 64)
		if e != nil || priority < 0 || priority > 1 {
			return false
		}
	}
	if !goodqaStringField(annotations, "lastModified", false) {
		return false
	}
	return true
}
