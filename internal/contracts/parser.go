package contracts

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var secretPatterns = []struct {
	name string
	rx   *regexp.Regexp
}{
	{"OpenAI-style key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{12,}`)},
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"bearer token", regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}`)},
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
	{"inline secret assignment", regexp.MustCompile(`(?im)\b[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{8,}`)},
}

func ParseFile(filename string) (*Contract, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read contract: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Contract, error) {
	if name := literalSecretKind(string(data)); name != "" {
		return nil, ValidationErrors{{Field: "contract", Message: "contains a literal " + name + "; reference an environment variable instead"}}
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return nil, fmt.Errorf("decode contract: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode contract: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("decode contract: %w", err)
	}

	if err := contract.Validate(); err != nil {
		return nil, err
	}
	return &contract, nil
}

func literalSecretKind(data string) string {
	for _, candidate := range secretPatterns {
		for _, match := range candidate.rx.FindAllString(data, -1) {
			if strings.Contains(match, "${") || strings.Contains(match, "$ENV") {
				continue
			}
			return candidate.name
		}
	}
	return ""
}
