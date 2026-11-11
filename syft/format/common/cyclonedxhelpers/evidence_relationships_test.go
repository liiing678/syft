package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	cdxhelpers "github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const (
	lockPath     = "/app/package-lock.json"
	metadataPath = "/app/node_modules/alpha/package.json"
)

// evidenceRelationshipFixture builds the synthetic three-package, two-evidence-kind SBOM used to
// verify reversible package-to-file evidence mapping:
//   - three npm packages with dependency-of edges pointing at the root package
//   - a lock file and a package metadata file connected through Contains and EvidentBy edges
//   - one primary and one supporting evidence category
func evidenceRelationshipFixture(t *testing.T) sbom.SBOM {
	t.Helper()

	alpha := pkg.Package{Name: "alpha", Version: "1.0", Type: pkg.NpmPkg, PURL: "pkg:npm/alpha@1.0"}
	beta := pkg.Package{Name: "beta", Version: "2.0", Type: pkg.NpmPkg, PURL: "pkg:npm/beta@2.0"}
	gamma := pkg.Package{Name: "gamma", Version: "3.0", Type: pkg.NpmPkg, PURL: "pkg:npm/gamma@3.0"}
	alpha.SetID()
	beta.SetID()
	gamma.SetID()

	lock := file.Coordinates{RealPath: lockPath}
	metadata := file.Coordinates{RealPath: metadataPath}

	primaryLocation := file.NewLocationFromCoordinates(lock).
		WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	supportingLocation := file.NewLocationFromCoordinates(metadata).
		WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)
	alpha.Locations = file.NewLocationSet(primaryLocation, supportingLocation)
	beta.Locations = file.NewLocationSet(file.NewLocationFromCoordinates(lock))
	gamma.Locations = file.NewLocationSet(file.NewLocationFromCoordinates(lock))

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(alpha, beta, gamma),
			FileMetadata: map[file.Coordinates]file.Metadata{
				lock:     {},
				metadata: {},
			},
		},
		Relationships: []artifact.Relationship{
			// native dependency edges: these must remain in the dependencies section
			{From: beta, To: alpha, Type: artifact.DependencyOfRelationship},
			{From: gamma, To: alpha, Type: artifact.DependencyOfRelationship},

			// containment edges in both directions syft records
			{From: alpha, To: lock, Type: artifact.ContainsRelationship},
			{From: lock, To: beta, Type: artifact.ContainsRelationship},

			// evidence edges carrying their categories
			{From: alpha, To: lock, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}},
			{From: alpha, To: metadata, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": pkg.SupportingEvidenceAnnotation}},
		},
	}
}

// testEndpoint identifies a relationship endpoint independently of the format-specific ID so
// round trips can be compared by package name or file path rather than internal fingerprints.
type testEndpoint struct {
	kind string
	name string
}

func endpointOf(identifiable artifact.Identifiable) testEndpoint {
	switch value := identifiable.(type) {
	case pkg.Package:
		return testEndpoint{kind: "package", name: value.Name}
	case file.Coordinates:
		return testEndpoint{kind: "file", name: value.RealPath}
	default:
		return testEndpoint{kind: "unknown", name: string(identifiable.ID())}
	}
}

type expectedEdge struct {
	from testEndpoint
	to   testEndpoint
	typ  artifact.RelationshipType
	data map[string]string
}

func edgeKey(e expectedEdge) string {
	return string(e.typ) + ":" + e.from.name + "->" + e.to.name
}

func TestToFormatModel_evidenceRelationshipsAreReversible(t *testing.T) {
	input := evidenceRelationshipFixture(t)

	bom := ToFormatModel(input)

	// dependency edges remain native and untouched
	require.NotNil(t, bom.Dependencies)
	var dependencyRefs []string
	for _, dep := range *bom.Dependencies {
		for _, ref := range *dep.Dependencies {
			dependencyRefs = append(dependencyRefs, dep.Ref+"<-"+ref)
		}
	}
	alpha := mustPackage(t, input, "alpha")
	beta := mustPackage(t, input, "beta")
	gamma := mustPackage(t, input, "gamma")
	assert.ElementsMatch(t, []string{
		cdxhelpers.DeriveBomRef(alpha) + "<-" + cdxhelpers.DeriveBomRef(beta),
		cdxhelpers.DeriveBomRef(alpha) + "<-" + cdxhelpers.DeriveBomRef(gamma),
	}, dependencyRefs)

	// the four non-dependency edges are carried as deterministic BOM properties:
	// three properties per edge plus one evidence property for each of the two evident-by edges
	require.NotNil(t, bom.Properties)
	assert.Len(t, *bom.Properties, 4*3+2)

	decoded, err := cdxhelpers.ToSyftModel(bom)
	require.NoError(t, err)

	expected := []expectedEdge{
		{from: testEndpoint{"package", "beta"}, to: testEndpoint{"package", "alpha"}, typ: artifact.DependencyOfRelationship},
		{from: testEndpoint{"package", "gamma"}, to: testEndpoint{"package", "alpha"}, typ: artifact.DependencyOfRelationship},
		{from: testEndpoint{"package", "alpha"}, to: testEndpoint{"file", lockPath}, typ: artifact.ContainsRelationship},
		{from: testEndpoint{"file", lockPath}, to: testEndpoint{"package", "beta"}, typ: artifact.ContainsRelationship},
		{from: testEndpoint{"package", "alpha"}, to: testEndpoint{"file", lockPath}, typ: artifact.EvidentByRelationship,
			data: map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}},
		{from: testEndpoint{"package", "alpha"}, to: testEndpoint{"file", metadataPath}, typ: artifact.EvidentByRelationship,
			data: map[string]string{"kind": pkg.SupportingEvidenceAnnotation}},
	}

	got := map[string]artifact.Relationship{}
	for _, r := range decoded.Relationships {
		e := expectedEdge{from: endpointOf(r.From), to: endpointOf(r.To), typ: r.Type, data: dataMap(r.Data)}
		got[edgeKey(e)] = r
	}

	require.Len(t, got, len(expected))
	for _, want := range expected {
		actual, ok := got[edgeKey(want)]
		require.True(t, ok, "missing relationship %s", edgeKey(want))
		assert.Equal(t, want.from, endpointOf(actual.From))
		assert.Equal(t, want.to, endpointOf(actual.To))
		assert.Equal(t, want.typ, actual.Type)
		assert.Equal(t, want.data, dataMap(actual.Data))
	}

	// the package bom-refs are unchanged by the new properties
	assert.Equal(t, cdxhelpers.DeriveBomRef(alpha), componentBomRef(bom, cdxhelpers.DeriveBomRef(alpha)))
	assert.Equal(t, cdxhelpers.DeriveBomRef(beta), componentBomRef(bom, cdxhelpers.DeriveBomRef(beta)))
}

func dataMap(data any) map[string]string {
	if data == nil {
		return nil
	}
	m, ok := data.(map[string]string)
	if !ok {
		return nil
	}
	return m
}

func mustPackage(t *testing.T, s sbom.SBOM, name string) pkg.Package {
	t.Helper()
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Name == name {
			return p
		}
	}
	require.Failf(t, "package not found", "package %s not found", name)
	return pkg.Package{}
}

func componentBomRef(bom *cyclonedx.BOM, ref string) string {
	for _, component := range *bom.Components {
		if component.BOMRef == ref {
			return component.BOMRef
		}
	}
	return ""
}
