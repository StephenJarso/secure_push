package detectors
import(
	"path/filepath"
	"strings"
)
type EnvDetector struct{}

func(d *EnvDetector) Name() string{
	return "ENV_FILE"
}
func(d *EnvDetector) Severity()Severity{
	return Critical
}
 func(d *EnvDetector)Detect(content string,filename string)([]Finding,error){
	base :=filepath.Base(filename)
	if strings.HasPrefix(base, ".env"){
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Message:  ".env file should not be committed",
		}}, nil
	}
	return nil,nil
 }

