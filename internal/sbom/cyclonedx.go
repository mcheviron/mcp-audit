package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

type Bom struct {
	XMLName      xml.Name        `json:"-" xml:"bom"`
	XMLNS        string          `json:"-" xml:"xmlns,attr"`
	BomFormat    string          `json:"bomFormat" xml:"-"`
	SpecVersion  string          `json:"specVersion" xml:"-"`
	SerialNumber string          `json:"serialNumber" xml:"serialNumber"`
	Version      int             `json:"version" xml:"version"`
	Metadata     Metadata        `json:"metadata" xml:"metadata"`
	Components   []Component     `json:"components" xml:"components>component"`
	Vulns        []Vulnerability `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp" xml:"timestamp"`
	Tools     []Tool     `json:"tools" xml:"tools>tool"`
	Component *Component `json:"component,omitempty" xml:"component,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor" xml:"vendor"`
	Name    string `json:"name" xml:"name"`
	Version string `json:"version" xml:"version"`
}

type Component struct {
	BomRef      string    `json:"bom-ref" xml:"bom-ref,attr"`
	Type        string    `json:"type" xml:"type,attr"`
	Name        string    `json:"name" xml:"name"`
	Version     string    `json:"version" xml:"version"`
	Description string    `json:"description,omitempty" xml:"description,omitempty"`
	Purl        string    `json:"purl,omitempty" xml:"purl,omitempty"`
	Supplier    *Supplier `json:"supplier,omitempty" xml:"supplier,omitempty"`
}

type Supplier struct {
	Name string `json:"name" xml:"name"`
}

type Vulnerability struct {
	BomRef  string       `json:"bom-ref" xml:"bom-ref,attr"`
	ID      string       `json:"id" xml:"id"`
	Source  *VulnSource  `json:"source,omitempty" xml:"source,omitempty"`
	Ratings []VulnRating `json:"ratings,omitempty" xml:"ratings>rating,omitempty"`
	Affects []Affect     `json:"affects,omitempty" xml:"affects>affect,omitempty"`
	Detail  string       `json:"detail,omitempty" xml:"detail,omitempty"`
}

type VulnSource struct {
	Name string `json:"name" xml:"name"`
	URL  string `json:"url,omitempty" xml:"url,omitempty"`
}

type VulnRating struct {
	Source   *VulnSource `json:"source,omitempty" xml:"source,omitempty"`
	Score    float64     `json:"score,omitempty" xml:"score,omitempty"`
	Severity string      `json:"severity" xml:"severity"`
	Method   string      `json:"method" xml:"method"`
	Vector   string      `json:"vector,omitempty" xml:"vector,omitempty"`
}

type Affect struct {
	Ref string `json:"ref" xml:"ref"`
}

type DiscoveredServer struct {
	Name      string
	Package   string
	Version   string
	Transport string
	Publisher string
}

type CVEResult struct {
	ID          string
	CVSSScore   float64
	Description string
	URL         string
}

func NewCycloneDX(servers []DiscoveredServer, cves map[string][]CVEResult, ver string) Bom {
	components := make([]Component, len(servers))
	for i, srv := range servers {
		pkg := srv.Package
		if pkg == "" {
			pkg = srv.Name
		}
		compVer := srv.Version
		if compVer == "" {
			compVer = "unknown"
		}
		components[i] = Component{
			BomRef:      fmt.Sprintf("pkg:npm/%s@%s", pkg, compVer),
			Type:        "application",
			Name:        pkg,
			Version:     compVer,
			Description: fmt.Sprintf("%s MCP server", srv.Transport),
			Purl:        fmt.Sprintf("pkg:npm/%s@%s", pkg, compVer),
		}
		if srv.Publisher != "" {
			components[i].Supplier = &Supplier{Name: srv.Publisher}
		}
	}

	var vulns []Vulnerability
	for pkg, entries := range cves {
		for _, cve := range entries {
			vuln := Vulnerability{
				BomRef: fmt.Sprintf("vuln/%s/%s", pkg, cve.ID),
				ID:     cve.ID,
				Source: &VulnSource{
					Name: "NVD",
					URL:  cve.URL,
				},
				Ratings: []VulnRating{{
					Score:    cve.CVSSScore,
					Severity: cvssSeverityLower(cvssToSeverity(cve.CVSSScore)),
					Method:   "CVSSv3",
				}},
				Affects: []Affect{{Ref: fmt.Sprintf("pkg:npm/%s", pkg)}},
				Detail:  cve.Description,
			}
			vulns = append(vulns, vuln)
		}
	}

	return Bom{
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", newUUID()),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{{
				Vendor:  "mcp-audit",
				Name:    "mcp-audit",
				Version: ver,
			}},
		},
		Components: components,
		Vulns:      vulns,
	}
}

func (b Bom) ToJSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

func (b Bom) ToXML() ([]byte, error) {
	output, err := xml.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), output...), nil
}

func NewDiscoveredServers(cfgs []config.Config) []DiscoveredServer {
	var servers []DiscoveredServer
	for _, cfg := range cfgs {
		for _, srv := range cfg.Servers {
			servers = append(servers, DiscoveredServer{
				Name:      srv.Name,
				Package:   srv.Package,
				Version:   "",
				Transport: srv.Transport,
			})
		}
	}
	return servers
}

func cvssToSeverity(score float64) scanner.Severity {
	switch {
	case score >= 9.0:
		return scanner.SevCritical
	case score >= 7.0:
		return scanner.SevHigh
	case score >= 4.0:
		return scanner.SevMedium
	default:
		return scanner.SevLow
	}
}

func cvssSeverityLower(sev scanner.Severity) string {
	return sev.StringLower()
}

func newUUID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		now&0xffffffff,
		now>>32&0xffff,
		now>>48&0xffff|0x4000,
		now>>32&0x3fff|0x8000,
		now&0xffffffffffff)
}
