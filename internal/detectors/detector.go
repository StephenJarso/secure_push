package detectors

type Severity string

const(
	Critical Severity ="CRITICAL"
	High Severity  = "HIGH"
	Medium Severity = "MEDIUM"
	Low Severity = "LOW"
)
type Finding struct{
Severity Severity
Rule string
File string
Line int
Message string
}
//detector is an interface you can add new rules without having to change anything in scanner
type Detector interface{
	Severity() Severity
	Name() string
	Detect(content string,filename string)([]Finding,error)
}