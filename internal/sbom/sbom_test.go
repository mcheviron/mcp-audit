package sbom

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
)

func TestCycloneDXJSONValid(t *testing.T) {
	servers := []DiscoveredServer{
		{Name: "filesystem", Package: "@modelcontextprotocol/server-filesystem", Version: "1.2.0", Transport: "stdio", Publisher: "Anthropic"},
		{Name: "memory", Package: "@modelcontextprotocol/server-memory", Version: "", Transport: "stdio"},
	}
	bom := NewCycloneDX(servers, nil, "0.1.0")
	data, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", parsed["specVersion"])
	}
}

func TestCycloneDXComponentCount(t *testing.T) {
	servers := []DiscoveredServer{
		{Name: "a", Package: "pkg-a", Transport: "stdio"},
		{Name: "b", Package: "pkg-b", Transport: "sse"},
		{Name: "c", Package: "pkg-c", Transport: "stdio"},
	}
	bom := NewCycloneDX(servers, nil, "dev")
	if len(bom.Components) != 3 {
		t.Errorf("components = %d, want 3", len(bom.Components))
	}
}

func TestCycloneDXCVEIncluded(t *testing.T) {
	servers := []DiscoveredServer{
		{Name: "fs", Package: "filesystem", Transport: "stdio"},
	}
	cves := map[string][]CVEResult{
		"filesystem": {{ID: "CVE-2025-1234", CVSSScore: 8.5, Description: "SSRF", URL: "https://nvd.nist.gov/CVE-2025-1234"}},
	}
	bom := NewCycloneDX(servers, cves, "dev")
	if len(bom.Vulns) != 1 {
		t.Fatalf("vulns = %d, want 1", len(bom.Vulns))
	}
	if bom.Vulns[0].ID != "CVE-2025-1234" {
		t.Errorf("vuln ID = %s, want CVE-2025-1234", bom.Vulns[0].ID)
	}
	if bom.Vulns[0].Ratings[0].Severity != "high" {
		t.Errorf("severity = %s, want high", bom.Vulns[0].Ratings[0].Severity)
	}
}

func TestCycloneDXNoCVEs(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	bom := NewCycloneDX(servers, nil, "dev")
	if bom.Vulns != nil {
		t.Errorf("vulns should be nil when no CVEs, got %d", len(bom.Vulns))
	}
}

func TestCycloneDXVersionUnknown(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	bom := NewCycloneDX(servers, nil, "dev")
	if bom.Components[0].Version != "unknown" {
		t.Errorf("version = %s, want unknown", bom.Components[0].Version)
	}
}

func TestCycloneDXSupplierPresent(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio", Publisher: "Anthropic"}}
	bom := NewCycloneDX(servers, nil, "dev")
	if bom.Components[0].Supplier == nil {
		t.Fatal("supplier should not be nil")
	}
	if bom.Components[0].Supplier.Name != "Anthropic" {
		t.Errorf("supplier = %s, want Anthropic", bom.Components[0].Supplier.Name)
	}
}

func TestCycloneDXSupplierAbsent(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	bom := NewCycloneDX(servers, nil, "dev")
	if bom.Components[0].Supplier != nil {
		t.Errorf("supplier should be nil, got %v", bom.Components[0].Supplier)
	}
}

func TestCycloneDXXMLValid(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	bom := NewCycloneDX(servers, nil, "dev")
	data, err := bom.ToXML()
	if err != nil {
		t.Fatalf("ToXML: %v", err)
	}
	if !strings.HasPrefix(string(data), xml.Header) {
		t.Error("XML should start with XML header")
	}
	var parsed Bom
	if err := xml.Unmarshal(data[len(xml.Header):], &parsed); err != nil {
		t.Fatalf("unmarshal XML: %v", err)
	}
}

func TestSPDXJSONValid(t *testing.T) {
	servers := []DiscoveredServer{
		{Name: "filesystem", Package: "@modelcontextprotocol/server-filesystem", Version: "1.2.0", Transport: "stdio", Publisher: "Anthropic"},
	}
	doc := NewSPDX(servers, nil, "0.1.0")
	data, err := doc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3", parsed["spdxVersion"])
	}
}

func TestSPDXSPDXIDFormat(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "my-pkg", Transport: "stdio"}}
	doc := NewSPDX(servers, nil, "dev")
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %s, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.Packages[0].SPDXID != "SPDXRef-Package-my-pkg" {
		t.Errorf("package SPDXID = %s, want SPDXRef-Package-my-pkg", doc.Packages[0].SPDXID)
	}
}

func TestSPDXTagValueHeaders(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	doc := NewSPDX(servers, nil, "dev")
	data, err := doc.ToTagValue()
	if err != nil {
		t.Fatalf("ToTagValue: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "SPDXVersion: SPDX-2.3") {
		t.Error("tag-value should contain SPDXVersion: SPDX-2.3")
	}
	if !strings.Contains(out, "DataLicense: CC0-1.0") {
		t.Error("tag-value should contain DataLicense: CC0-1.0")
	}
	if !strings.Contains(out, "PackageName: filesystem") {
		t.Error("tag-value should contain PackageName: filesystem")
	}
}

func TestSPDXCVERefs(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	cves := map[string][]CVEResult{
		"filesystem": {{ID: "CVE-2025-1234", CVSSScore: 8.5, Description: "SSRF", URL: "https://nvd.nist.gov"}},
	}
	doc := NewSPDX(servers, cves, "dev")
	found := false
	for _, ref := range doc.Packages[0].ExternalRefs {
		if ref.Category == "SECURITY" && ref.Locator == "CVE-2025-1234" {
			found = true
		}
	}
	if !found {
		t.Error("SPDX should contain SECURITY external ref for CVE-2025-1234")
	}
}

func TestSPDXVersionUnknown(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio"}}
	doc := NewSPDX(servers, nil, "dev")
	if doc.Packages[0].VersionInfo != "unknown" {
		t.Errorf("version = %s, want unknown", doc.Packages[0].VersionInfo)
	}
}

func TestSPDXSupplierFormat(t *testing.T) {
	servers := []DiscoveredServer{{Name: "fs", Package: "filesystem", Transport: "stdio", Publisher: "Anthropic"}}
	doc := NewSPDX(servers, nil, "dev")
	if doc.Packages[0].Supplier != "Organization: Anthropic" {
		t.Errorf("supplier = %s, want 'Organization: Anthropic'", doc.Packages[0].Supplier)
	}
}

func TestSPDXRelationships(t *testing.T) {
	servers := []DiscoveredServer{
		{Name: "a", Package: "pkg-a", Transport: "stdio"},
		{Name: "b", Package: "pkg-b", Transport: "stdio"},
	}
	doc := NewSPDX(servers, nil, "dev")
	if len(doc.Relationships) != 2 {
		t.Errorf("relationships = %d, want 2", len(doc.Relationships))
	}
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-DOCUMENT" {
			t.Errorf("relationship source = %s, want SPDXRef-DOCUMENT", rel.SPDXElementID)
		}
		if rel.RelationshipType != "DESCRIBES" {
			t.Errorf("relationship type = %s, want DESCRIBES", rel.RelationshipType)
		}
	}
}

func TestNewDiscoveredServers(t *testing.T) {
	cfgs := []config.Config{{
		Servers: []config.ServerEntry{
			{Name: "fs", Package: "filesystem", Transport: "stdio"},
		},
	}}
	servers := NewDiscoveredServers(cfgs)
	if len(servers) != 1 {
		t.Fatalf("servers = %d, want 1", len(servers))
	}
	if servers[0].Name != "fs" {
		t.Errorf("name = %s, want fs", servers[0].Name)
	}
	if servers[0].Package != "filesystem" {
		t.Errorf("package = %s, want filesystem", servers[0].Package)
	}
}

func TestEmptyInventory(t *testing.T) {
	bom := NewCycloneDX(nil, nil, "dev")
	if len(bom.Components) != 0 {
		t.Errorf("components = %d, want 0", len(bom.Components))
	}
	data, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comps, ok := parsed["components"].([]any)
	if !ok {
		t.Fatal("components should be an array")
	}
	if len(comps) != 0 {
		t.Errorf("components array should be empty, got %d", len(comps))
	}
}
