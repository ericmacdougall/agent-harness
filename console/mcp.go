package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type stdioMCPServer struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}
type stdioMCPConfig struct {
	Servers map[string]stdioMCPServer `json:"mcpServers"`
}

// The immutable admission digest gives each profile/revision its own stable
// namespace. Repeated policy resolution must not change a running client hash.
func goodqaMCPServerName(digest string) (string, error) {
	if !validSettingsDigest(digest) {
		return "", errors.New("invalid MCP admission generation")
	}
	return "agent_harness_goodqa_" + digest[:24], nil
}

func validateMCPConfig(path, digest string) (stdioMCPConfig, error) {
	result := stdioMCPConfig{}
	if path == "" {
		return result, nil
	}
	data, e := settingsRead(path, 65536)
	if e != nil || settingsDigest(data) != digest || settingsDecode(data, &result) != nil {
		return result, errors.New("MCP metadata changed or is invalid")
	}
	if len(result.Servers) != 1 {
		return result, errors.New("only admitted GoodQA helper is supported")
	}
	var name string
	var server stdioMCPServer
	for key, value := range result.Servers {
		name, server = key, value
	}
	if server.Type != "stdio" || len(server.Args) != 5 || server.Args[0] != "--goodqa-proxy" || server.Args[1] != "--config" || server.Args[3] != "--sha256" {
		return result, errors.New("unsupported MCP helper invocation")
	}
	want, e := goodqaMCPServerName(server.Args[4])
	if e != nil || name != want {
		return result, errors.New("MCP helper namespace does not match admitted generation")
	}
	binary, e := os.Executable()
	if e != nil {
		return result, e
	}
	binary, e = filepath.EvalSymlinks(binary)
	if e != nil || server.Command != binary {
		return result, errors.New("MCP helper must be this console executable")
	}
	if _, e = loadGoodQASnapshot(server.Args[2], server.Args[4]); e != nil {
		return result, e
	}
	return result, nil
}
func codexMCPArgs(path, digest string) ([]string, error) {
	config, e := validateMCPConfig(path, digest)
	if e != nil {
		return nil, e
	}
	if len(config.Servers) == 0 {
		return []string{}, nil
	}
	var name string
	var server stdioMCPServer
	for key, value := range config.Servers {
		name, server = key, value
	}
	args := []string{"-c", "mcp_servers." + name + ".command=" + strconv.Quote(server.Command)}
	quoted := []string{}
	for _, arg := range server.Args {
		quoted = append(quoted, strconv.Quote(arg))
	}
	return append(args, "-c", "mcp_servers."+name+".args=["+strings.Join(quoted, ",")+"]"), nil
}
