package govlint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowedSQLTimeClasses are the only temporary or non-authoritative reasons a
// SQL text-time comparison/order site may remain. S2-S4 delete the migration
// classes as each table family moves to numeric authority; this map must never
// gain another migration class.
var allowedSQLTimeClasses = map[string]string{
	"s4_semantics_review": "remaining insertion-order versus chronological-order sites scheduled for rc7 Session 4",
	"display_only":        "read-only presentation ordering with no authority or routing effect",
	"export_only":         "offline export ordering with no authority or routing effect",
}

var sqlTimeColumnPattern = regexp.MustCompile(`(?i)\b(created|created_at|updated_at|expires_at|reserved_at|lease_until|reset_at|settled_at)\b`)
var sqlTimeComparisonPattern = regexp.MustCompile(`(?i)(\b(?:created|created_at|updated_at|expires_at|reserved_at|lease_until|reset_at|settled_at)\b\s*(?:<=|>=|<>|<|>)|(?:<=|>=|<>|<|>)\s*\b(?:created|created_at|updated_at|expires_at|reserved_at|lease_until|reset_at|settled_at)\b)`)
var sqlOrderByPattern = regexp.MustCompile(`(?is)\border\s+by\b([^;]*)`)

func TestSQLTimestampRatchet(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	var violations []string
	for _, root := range []string{filepath.Join(repoRoot, "internal"), filepath.Join(repoRoot, "cmd")} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(repoRoot, path)
			hits, err := scanFileForUnsafeSQLTime(path, rel)
			if err != nil {
				return err
			}
			violations = append(violations, hits...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("SQL timestamp ratchet: %d unmarked/invalid site(s):\n%s\n\nEvery SQL literal that compares or orders a legacy text timestamp must carry an adjacent //govratchet:sql-time-allow(<class>) marker naming one of: %s.", len(violations), strings.Join(violations, "\n"), strings.Join(sortedSQLTimeClassNames(), ", "))
	}
}

func scanFileForUnsafeSQLTime(path, label string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var violations []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil || !unsafeSQLTime(value) {
			return true
		}
		line := fset.Position(literal.Pos()).Line
		class, marked := sqlTimeMarkerNearLine(fset, file, line)
		switch {
		case !marked:
			violations = append(violations, fmt.Sprintf("%s:%d: SQL text-time comparison/order has no //govratchet:sql-time-allow(<class>) marker", label, line))
		case allowedSQLTimeClasses[class] == "":
			violations = append(violations, fmt.Sprintf("%s:%d: //govratchet:sql-time-allow(%s) cites an unrecognized class", label, line, class))
		}
		return true
	})
	return violations, nil
}

func unsafeSQLTime(value string) bool {
	for _, match := range sqlTimeComparisonPattern.FindAllString(value, -1) {
		if !strings.Contains(match, "<>") {
			return true
		}
	}
	for _, match := range sqlOrderByPattern.FindAllStringSubmatch(value, -1) {
		if sqlTimeColumnPattern.MatchString(match[1]) {
			return true
		}
	}
	return false
}

func sqlTimeMarkerNearLine(fset *token.FileSet, file *ast.File, line int) (string, bool) {
	for _, group := range file.Comments {
		for _, comment := range group.List {
			commentLine := fset.Position(comment.Pos()).Line
			if commentLine != line && commentLine != line-1 {
				continue
			}
			const marker = "govratchet:sql-time-allow("
			index := strings.Index(comment.Text, marker)
			if index < 0 {
				continue
			}
			rest := comment.Text[index+len(marker):]
			end := strings.Index(rest, ")")
			if end >= 0 {
				return rest[:end], true
			}
		}
	}
	return "", false
}

func sortedSQLTimeClassNames() []string {
	names := make([]string, 0, len(allowedSQLTimeClasses))
	for name := range allowedSQLTimeClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestSQLTimestampRatchetDetectsComparisonOrderingAndInvalidMarkers(t *testing.T) {
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "fixture.go")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name string
		body string
		want int
	}{
		{"comparison", "package fixture\nvar q = `SELECT * FROM x WHERE expires_at>?`\n", 1},
		{"ordering", "package fixture\nvar q = `SELECT * FROM x ORDER BY created_at DESC`\n", 1},
		{"not-equal sentinel is not chronological", "package fixture\nvar q = `SELECT * FROM x WHERE expires_at<>''`\n", 0},
		{"numeric replacement", "package fixture\nvar q = `SELECT * FROM x WHERE expires_unix_nano>? ORDER BY created_unix_nano`\n", 0},
		{"valid marker", "package fixture\n// govratchet:sql-time-allow(s4_semantics_review)\nvar q = `SELECT * FROM x WHERE expires_at>?`\n", 0},
		{"invalid marker", "package fixture\n// govratchet:sql-time-allow(made_up)\nvar q = `SELECT * FROM x ORDER BY created_at`\n", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := scanFileForUnsafeSQLTime(write(test.body), "fixture.go")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != test.want {
				t.Fatalf("violations = %v, want count %d", got, test.want)
			}
		})
	}
}
