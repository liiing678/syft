package spdxhelpers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const (
	spdxLockPath     = "/app/package-lock.json"
	spdxMetadataPath = "/app/node_modules/alpha/package.json"
)

// spdxEvidenceFixture is the SPDX counterpart of the CycloneDX synthetic fixture: three
// packages, two evidence files, both Contains and EvidentBy edges, and one edge per evidence
// category.
func spdxEvidenceFixture(t *testing.T) sbom.SBOM {
	t.Helper()

	alpha := pkg.Package{Name: "alpha", Version: "1.0", Type: pkg.NpmPkg, PURL: "pkg:npm/alpha@1.0"}
	beta := pkg.Package{Name: "beta", Version: "2.0", Type: pkg.NpmPkg, PURL: "pkg:npm/beta@2.0"}
	gamma := pkg.Package{Name: "gamma", Version: "3.0", Type: pkg.NpmPkg, PURL: "pkg:npm/gamma@3.0"}
	alpha.SetID()
	beta.SetID()
	gamma.SetID()

	lock := file.Coordinates{RealPath: spdxLockPath}
	metadata := file.Coordinates{RealPath: spdxMetadataPath}

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(alpha, beta, gamma),
			FileMetadata: map[file.Coordinates]file.Metadata{
				lock:     {},
				metadata: {},
			},
		},
		Relationships: []artifact.Relationship{
			{From: beta, To: alpha, Type: artifact.DependencyOfRelationship},
			{From: gamma, To: alpha, Type: artifact.DependencyOfRelationship},
			{From: alpha, To: lock, Type: artifact.ContainsRelationship},
			{From: lock, To: beta, Type: artifact.ContainsRelationship},
			{From: alpha, To: lock, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}},
			{From: alpha, To: metadata, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": pkg.SupportingEvidenceAnnotation}},
		},
	}
}

func TestEvidentByCommentIsReversible(t *testing.T) {
	primary := artifact.Relationship{
		Type: artifact.EvidentByRelationship,
		Data: map[string]string{"kind": pkg.PrimaryEvidenceAnnotation},
	}
	supporting := artifact.Relationship{
		Type: artifact.EvidentByRelationship,
		Data: map[string]string{"kind": pkg.SupportingEvidenceAnnotation},
	}

	assert.Contains(t, evidentByComment(primary), "; evidence:primary")
	assert.Contains(t, evidentByComment(supporting), "; evidence:supporting")

	assert.Equal(t,
		map[string]string{"kind": pkg.PrimaryEvidenceAnnotation},
		evidentByData(evidentByComment(primary)))
	assert.Equal(t,
		map[string]string{"kind": pkg.SupportingEvidenceAnnotation},
		evidentByData(evidentByComment(supporting)))

	// a legacy comment without the marker still recovers the edge, defaulting to supporting
	assert.Equal(t,
		map[string]string{"kind": pkg.SupportingEvidenceAnnotation},
		evidentByData("evident-by: indicates the package's existence is evident by the given file"))

	// an unrecognized evidence value never invents a category beyond the two known ones
	assert.Equal(t,
		map[string]string{"kind": pkg.SupportingEvidenceAnnotation},
		evidentByData("evident-by: ...; evidence:bogus"))
}

func TestSPDXEvidenceRelationshipRoundTrip(t *testing.T) {
	input := spdxEvidenceFixture(t)

	document := ToFormatModel(input)

	// the encoded document keeps both evidence edges and both categories in OTHER comments
	comments := map[string]string{}
	for _, r := range document.Relationships {
		if r.Relationship == "OTHER" {
			comments[string(r.RefB.ElementRefID)] = r.RelationshipComment
		}
	}
	require.Len(t, comments, 2)
	var hasPrimary, hasSupporting bool
	for _, comment := range comments {
		if assert.Contains(t, comment, "evident-by:") {
			switch {
			case strings.Contains(comment, "; evidence:primary"):
				hasPrimary = true
			case strings.Contains(comment, "; evidence:supporting"):
				hasSupporting = true
			}
		}
	}
	assert.True(t, hasPrimary)
	assert.True(t, hasSupporting)

	roundTripped, err := ToSyftModel(document)
	require.NoError(t, err)

	edges := map[string]artifact.Relationship{}
	for _, r := range roundTripped.Relationships {
		from, to := spdxEndpointName(r.From), spdxEndpointName(r.To)
		edges[string(r.Type)+":"+from+"->"+to] = r
	}

	lock := file.Coordinates{RealPath: spdxLockPath}
	metadata := file.Coordinates{RealPath: spdxMetadataPath}
	lockName := normalizePath(lock.RealPath)
	metadataName := normalizePath(metadata.RealPath)

	expected := []struct {
		key  string
		from string
		to   string
		typ  artifact.RelationshipType
		data map[string]string
	}{
		{key: "dependency-of:beta->alpha", from: "beta", to: "alpha", typ: artifact.DependencyOfRelationship},
		{key: "dependency-of:gamma->alpha", from: "gamma", to: "alpha", typ: artifact.DependencyOfRelationship},
		{key: "contains:alpha->" + lockName, from: "alpha", to: lockName, typ: artifact.ContainsRelationship},
		{key: "contains:" + lockName + "->beta", from: lockName, to: "beta", typ: artifact.ContainsRelationship},
		{key: "evident-by:alpha->" + lockName, from: "alpha", to: lockName, typ: artifact.EvidentByRelationship,
			data: map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}},
		{key: "evident-by:alpha->" + metadataName, from: "alpha", to: metadataName, typ: artifact.EvidentByRelationship,
			data: map[string]string{"kind": pkg.SupportingEvidenceAnnotation}},
	}

	require.Len(t, edges, len(expected))
	for _, want := range expected {
		actual, ok := edges[want.key]
		require.True(t, ok, "missing %s", want.key)
		assert.Equal(t, want.from, spdxEndpointName(actual.From))
		assert.Equal(t, want.to, spdxEndpointName(actual.To))
		assert.Equal(t, want.typ, actual.Type)
		assert.Equal(t, want.data, spdxDataMap(actual.Data))
	}
}

func spdxEndpointName(identifiable artifact.Identifiable) string {
	switch value := identifiable.(type) {
	case pkg.Package:
		return value.Name
	case file.Coordinates:
		return normalizePath(value.RealPath)
	case file.Location:
		return normalizePath(value.RealPath)
	default:
		return string(identifiable.ID())
	}
}

func normalizePath(path string) string {
	return strings.TrimPrefix(path, "/")
}

func spdxDataMap(data any) map[string]string {
	if data == nil {
		return nil
	}
	m, ok := data.(map[string]string)
	if !ok {
		return nil
	}
	return m
}
