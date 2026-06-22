package detectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// ASTDetector performs AST-based analysis for Go files
type ASTDetector struct{}

func (d *ASTDetector) Name() string {
	return "AST_ANALYSIS"
}

func (d *ASTDetector) Severity() Severity {
	return Medium
}

// Detect performs AST-based analysis on Go source code
func (d *ASTDetector) Detect(content string, filename string) ([]Finding, error) {
	var findings []Finding

	// Only analyze Go files
	if !strings.HasSuffix(filename, ".go") {
		return nil, nil
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, content, parser.ParseComments)
	if err != nil {
		// If we can't parse the file, skip AST analysis
		return nil, nil
	}

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			// Check for potentially dangerous function calls
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := strings.ToLower(sel.Sel.Name)
				packageName := ""
				if ident, ok := sel.X.(*ast.Ident); ok {
					packageName = strings.ToLower(ident.Name)
				}
				if isDangerousFunction(packageName+"."+funcName) || isDangerousFunction(funcName) {
					findings = append(findings, Finding{
						Rule:     d.Name(),
						Severity: Medium,
						File:     filename,
						Line:     fset.Position(x.Pos()).Line,
						Message:  "Potentially dangerous function call: " + sel.Sel.Name,
					})
				}
			}
		case *ast.AssignStmt:
			// Check for hardcoded credentials in assignments
			for _, expr := range x.Rhs {
				if basicLit, ok := expr.(*ast.BasicLit); ok {
					if basicLit.Kind == token.STRING && isCredentialPattern(basicLit.Value) {
						findings = append(findings, Finding{
							Rule:     d.Name(),
							Severity: High,
							File:     filename,
							Line:     fset.Position(x.Pos()).Line,
							Message:  "Potential hardcoded credential in assignment",
						})
					}
				}
			}
		}
		return true
	})

	return findings, nil
}

func isDangerousFunction(name string) bool {
	dangerous := []string{
		"exec", "execcommand", "startprocess",
		"readfile", "writefile", "deletefile",
		"getenv", "setenv",
		"httpget", "httppost",
		"sqlopen", "dbquery",
		"eval", "evalstring",
		"compile", "mustcompile",
		"ioutil", "osopen",
	}
	for _, d := range dangerous {
		if strings.Contains(name, d) {
			return true
		}
	}
	return false
}

func isCredentialPattern(value string) bool {
	lower := strings.ToLower(value)
	patterns := []string{
		"password", "passwd", "pwd",
		"secret", "token", "api_key",
		"apikey", "access_key", "private_key",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// IsDangerousFunction exposes the dangerous function check for testing
func IsDangerousFunction(name string) bool {
	return isDangerousFunction(name)
}

// IsCredentialPattern exposes the credential pattern check for testing
func IsCredentialPattern(value string) bool {
	return isCredentialPattern(value)
}
