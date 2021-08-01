package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/library"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// Now returns the current time
var Now = time.Now

// regex to extract file path in case string includes (distro:version)
var re = regexp.MustCompile(`(?P<path>.+?)(?:\s*\((?:.*?)\).*?)?$`)

// Results to hold list of Result
type Results []Result

// Result to hold image scan results
type Result struct {
	Target          string                        `json:"Target"`
	Type            string                        `json:"Type,omitempty"`
	Packages        []ftypes.Package              `json:"Packages,omitempty"`
	Vulnerabilities []types.DetectedVulnerability `json:"Vulnerabilities"`
}

// WriteResults writes the result to output, format as passed in argument
func WriteResults(format string, output io.Writer, severities []dbTypes.Severity, results Results, outputTemplate string, light bool) error {
	var writer Writer
	switch format {
	case "table":
		writer = &TableWriter{Output: output, Light: light, Severities: severities}
	case "json":
		writer = &JSONWriter{Output: output}
	case "template":
		var err error
		if writer, err = NewTemplateWriter(output, outputTemplate); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	default:
		return xerrors.Errorf("unknown format: %v", format)
	}

	if err := writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}
	return nil
}

// Writer defines the result write operation
type Writer interface {
	Write(Results) error
}

// TableWriter implements Writer and output in tabular form
type TableWriter struct {
	Severities []dbTypes.Severity
	Output     io.Writer
	Light      bool
}

// Write writes the result on standard output
func (tw TableWriter) Write(results Results) error {
	for _, result := range results {
		// Skip zero vulnerabilities on Java archives (JAR/WAR/EAR)
		if result.Type == library.Jar && len(result.Vulnerabilities) == 0 {
			continue
		}
		tw.write(result)
	}
	return nil
}

func (tw TableWriter) write(result Result) {
	table := tablewriter.NewWriter(tw.Output)
	header := []string{"Library", "Vulnerability ID", "Severity", "Installed Version", "Fixed Version"}
	if !tw.Light {
		header = append(header, "Title")
	}
	table.SetHeader(header)
	severityCount := tw.setRows(table, result.Vulnerabilities)

	var results []string

	var severities []string
	for _, sev := range tw.Severities {
		severities = append(severities, sev.String())
	}

	for _, severity := range dbTypes.SeverityNames {
		if !utils.StringInSlice(severity, severities) {
			continue
		}
		r := fmt.Sprintf("%s: %d", severity, severityCount[severity])
		results = append(results, r)
	}

	fmt.Printf("\n%s\n", result.Target)
	fmt.Println(strings.Repeat("=", len(result.Target)))
	fmt.Printf("Total: %d (%s)\n\n", len(result.Vulnerabilities), strings.Join(results, ", "))

	if len(result.Vulnerabilities) == 0 {
		return
	}

	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.Render()
	return
}

func (tw TableWriter) setRows(table *tablewriter.Table, vulns []types.DetectedVulnerability) map[string]int {
	severityCount := map[string]int{}
	for _, v := range vulns {
		severityCount[v.Severity]++

		title := v.Title
		if title == "" {
			title = v.Description
		}
		splitTitle := strings.Split(title, " ")
		if len(splitTitle) >= 12 {
			title = strings.Join(splitTitle[:12], " ") + "..."
		}

		if len(v.PrimaryURL) > 0 {
			r := strings.NewReplacer("https://", "", "http://", "")
			title = fmt.Sprintf("%s -->%s", title, r.Replace(v.PrimaryURL))
		}

		var row []string
		if tw.Output == os.Stdout {
			row = []string{v.PkgName, v.VulnerabilityID, dbTypes.ColorizeSeverity(v.Severity),
				v.InstalledVersion, v.FixedVersion}
		} else {
			row = []string{v.PkgName, v.VulnerabilityID, v.Severity, v.InstalledVersion, v.FixedVersion}
		}

		if !tw.Light {
			row = append(row, strings.TrimSpace(title))
		}
		table.Append(row)
	}
	return severityCount
}

// JSONWriter implements result Writer
type JSONWriter struct {
	Output io.Writer
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(results Results) error {
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}

// TemplateWriter write result in custom format defined by user's template
type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

// NewTemplateWriter is the factory method to return TemplateWriter object
func NewTemplateWriter(output io.Writer, outputTemplate string) (*TemplateWriter, error) {
	if strings.HasPrefix(outputTemplate, "@") {
		buf, err := ioutil.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
		if err != nil {
			return nil, xerrors.Errorf("error retrieving template from path: %w", err)
		}
		outputTemplate = string(buf)
	}
	var templateFuncMap template.FuncMap
	templateFuncMap = sprig.GenericFuncMap()
	templateFuncMap["escapeXML"] = func(input string) string {
		escaped := &bytes.Buffer{}
		if err := xml.EscapeText(escaped, []byte(input)); err != nil {
			fmt.Printf("error while escapeString to XML: %v", err.Error())
			return input
		}
		return escaped.String()
	}
	templateFuncMap["toSarifErrorLevel"] = toSarifErrorLevel
	templateFuncMap["toSarifRuleName"] = toSarifRuleName
	templateFuncMap["endWithPeriod"] = func(input string) string {
		if !strings.HasSuffix(input, ".") {
			input += "."
		}
		return input
	}
	templateFuncMap["toLower"] = func(input string) string {
		return strings.ToLower(input)
	}
	templateFuncMap["escapeString"] = func(input string) string {
		return html.EscapeString(input)
	}
	templateFuncMap["toPathUri"] = func(input string) string {
		var matches = re.FindStringSubmatch(input)
		if matches != nil {
			input = matches[re.SubexpIndex("path")]
		}
		input = strings.ReplaceAll(input, "\\", "/")
		return input
	}
	templateFuncMap["getEnv"] = func(key string) string {
		return os.Getenv(key)
	}
	templateFuncMap["getCurrentTime"] = func() string {
		return Now().UTC().Format(time.RFC3339Nano)
	}
	tmpl, err := template.New("output template").Funcs(templateFuncMap).Parse(outputTemplate)
	if err != nil {
		return nil, xerrors.Errorf("error parsing template: %w", err)
	}
	return &TemplateWriter{Output: output, Template: tmpl}, nil
}

// Write writes result
func (tw TemplateWriter) Write(results Results) error {
	err := tw.Template.Execute(tw.Output, results)
	if err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}
	return nil
}

func toSarifRuleName(vulnerabilityType string) string {
	var ruleName string
	switch vulnerabilityType {
	case vulnerability.Ubuntu, vulnerability.Alpine, vulnerability.RedHat, vulnerability.RedHatOVAL,
		vulnerability.Debian, vulnerability.DebianOVAL, vulnerability.Fedora, vulnerability.Amazon,
		vulnerability.OracleOVAL, vulnerability.SuseCVRF, vulnerability.OpenSuseCVRF, vulnerability.Photon,
		vulnerability.CentOS:
		ruleName = "OS Package Vulnerability"
	case "npm", "yarn", "nuget", "pipenv", "poetry", "bundler", "cargo", "composer":
		ruleName = "Programming Language Vulnerability"
	default:
		ruleName = "Other Vulnerability"
	}
	return fmt.Sprintf("%s (%s)", ruleName, strings.Title(vulnerabilityType))
}

func toSarifErrorLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "UNKNOWN":
		return "note"
	default:
		return "none"
	}
}
