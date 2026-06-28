package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Relationships     []Relationship `json:"relationships,omitempty"`
}

type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo"`
	Supplier         string        `json:"supplier,omitempty"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	ExternalRefs     []ExternalRef `json:"externalRefs,omitempty"`
}

type ExternalRef struct {
	Category string `json:"category"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type Relationship struct {
	SPDXElementID      string `json:"spdxElementID"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

func NewSPDX(servers []DiscoveredServer, cves map[string][]CVEResult, ver string) Document {
	packages := make([]Package, len(servers))
	relationships := make([]Relationship, 0, len(servers))

	for i, srv := range servers {
		pkg := srv.Package
		if pkg == "" {
			pkg = srv.Name
		}
		pkgVer := srv.Version
		if pkgVer == "" {
			pkgVer = "unknown"
		}

		spdxID := fmt.Sprintf("SPDXRef-Package-%s", sanitizeID(pkg))
		supplier := ""
		if srv.Publisher != "" {
			supplier = fmt.Sprintf("Organization: %s", srv.Publisher)
		}

		externalRefs := []ExternalRef{{
			Category: "PACKAGE-MANAGER",
			Type:     "purl",
			Locator:  fmt.Sprintf("pkg:npm/%s@%s", pkg, pkgVer),
		}}

		if pkgCVEs, ok := cves[pkg]; ok {
			for _, cve := range pkgCVEs {
				externalRefs = append(externalRefs, ExternalRef{
					Category: "SECURITY",
					Type:     "cve",
					Locator:  cve.ID,
				})
			}
		}

		packages[i] = Package{
			SPDXID:           spdxID,
			Name:             pkg,
			VersionInfo:      pkgVer,
			Supplier:         supplier,
			DownloadLocation: fmt.Sprintf("https://registry.npmjs.org/%s", pkg),
			FilesAnalyzed:    false,
			ExternalRefs:     externalRefs,
		}

		relationships = append(relationships, Relationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSpdxElement: spdxID,
		})
	}

	return Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              sbomName(),
		DocumentNamespace: sbomNamespace(),
		CreationInfo: CreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{fmt.Sprintf("Tool: mcp-audit-%s", ver)},
		},
		Packages:      packages,
		Relationships: relationships,
	}
}

func (d Document) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func (d Document) ToTagValue() ([]byte, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "SPDXVersion: %s\n", d.SPDXVersion)
	fmt.Fprintf(&b, "DataLicense: %s\n", d.DataLicense)
	fmt.Fprintf(&b, "SPDXID: %s\n", d.SPDXID)
	fmt.Fprintf(&b, "DocumentName: %s\n", d.Name)
	fmt.Fprintf(&b, "DocumentNamespace: %s\n", d.DocumentNamespace)
	fmt.Fprintf(&b, "Creator: %s\n", d.CreationInfo.Creators[0])
	fmt.Fprintf(&b, "Created: %s\n", d.CreationInfo.Created)
	fmt.Fprintf(&b, "\n")

	for _, pkg := range d.Packages {
		fmt.Fprintf(&b, "PackageName: %s\n", pkg.Name)
		fmt.Fprintf(&b, "SPDXID: %s\n", pkg.SPDXID)
		fmt.Fprintf(&b, "PackageVersion: %s\n", pkg.VersionInfo)
		if pkg.Supplier != "" {
			fmt.Fprintf(&b, "PackageSupplier: %s\n", pkg.Supplier)
		}
		fmt.Fprintf(&b, "PackageDownloadLocation: %s\n", pkg.DownloadLocation)
		fmt.Fprintf(&b, "FilesAnalyzed: %t\n", pkg.FilesAnalyzed)
		for _, ref := range pkg.ExternalRefs {
			fmt.Fprintf(&b, "ExternalRef: %s %s %s\n", ref.Category, ref.Type, ref.Locator)
		}
		fmt.Fprintf(&b, "\n")
	}

	for _, rel := range d.Relationships {
		fmt.Fprintf(&b, "Relationship: %s %s %s\n", rel.SPDXElementID, rel.RelationshipType, rel.RelatedSpdxElement)
	}

	return []byte(b.String()), nil
}

func sbomName() string {
	return fmt.Sprintf("mcp-audit-sbom-%s-%d", time.Now().Format("20060102"), time.Now().UnixNano()%1000000)
}

func sbomNamespace() string {
	return fmt.Sprintf("https://mcp-audit.dev/sbom/%s-%d", time.Now().Format("20060102"), time.Now().UnixNano()%1000000)
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
