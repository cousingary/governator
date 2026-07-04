package prompts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var versionPattern = regexp.MustCompile("^v[0-9]{3}[.]md$")

type Version struct {
	ID       string
	Path     string
	Content  string
	Checksum string
}

func Latest(root, agent, mode string) (Version, error) {
	dir := filepath.Join(root, agent, mode)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Version{ID: "builtin"}, nil
		}
		return Version{}, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && versionPattern.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		return Version{ID: "builtin"}, nil
	}
	sort.Strings(names)
	name := names[len(names)-1]
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return Version{}, err
	}
	sum := sha256.Sum256(data)
	return Version{
		ID:       name[:len(name)-len(filepath.Ext(name))],
		Path:     path,
		Content:  string(data),
		Checksum: hex.EncodeToString(sum[:]),
	}, nil
}

func Resolve(root, agent, mode string) (Version, error) {
	version, err := Latest(root, agent, mode)
	if err != nil || version.ID != "builtin" || agent != "claude" {
		return version, err
	}
	return Latest(root, "claude-code", mode)
}

func Annotation(version Version) string {
	if version.ID == "builtin" {
		return ""
	}
	return fmt.Sprintf("\nPrompt registry version: %s checksum=%s\n%s\n", version.ID, version.Checksum, version.Content)
}
