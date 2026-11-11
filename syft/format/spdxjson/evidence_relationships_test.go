package spdxjson

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const (
	spdxJSONLockPath     = "/app/package-lock.json"
	spdxJSONMetadataPath = "/app/node_modules/alpha/package.json"
)

// spdxJSONEvidenceFixture is the SPDX synthetic fixture: three packages, two evidence files and
// both evidence categories, exercising the 2.3 and 3.0 encoders and their decoders.
func spdxJSONEvidenceFixture(t *testing.T) sbom.SBOM {
	t.Helper()

	alpha := pkg.Package{Name: "alpha", Version: "1.0", Type: pkg.NpmPkg, PURL: "pkg:npm/alpha@1.0"}
	beta := pkg.Package{Name: "beta", Version: "2.0", Type: pkg.NpmPkg, PURL: "pkg:npm/beta@2.0"}
	gamma := pkg.Package{Name: "gamma", Version: "3.0", Type: pkg.NpmPkg, PURL: "pkg:npm/gamma@3.0"}
	alpha.SetID()
	beta.SetID()
	gamma.SetID()

	lock := file.Coordinates{RealPath: spdxJSONLockPath}
	metadata := file.Coordinates{RealPath: spdxJSONMetadataPath}

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

func TestSPDXJSONEvidenceRelationshipRoundTrip(t *testing.T) {
	input := spdxJSONEvidenceFixture(t)

	versions := []string{"2.1", "2.2", "2.3", spdxutil.V3_0}
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: version})
			require.NoError(t, err)

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, input))

			decoded, formatID, decodedVersion, err := NewFormatDecoder().Decode(&buf)
			require.NoError(t, err)
			assert.Equal(t, ID, formatID)
			assert.Equal(t, version, decodedVersion)

			edges := map[string]artifact.Relationship{}
			for _, r := range decoded.Relationships {
				from := spdxJSONEndpointName(r.From)
				to := spdxJSONEndpointName(r.To)
				edges[string(r.Type)+":"+from+"->"+to] = r
			}

			lockName := spdxJSONLockPath[1:]
			metadataName := spdxJSONMetadataPath[1:]
			expected := []string{
				"dependency-of:beta->alpha",
				"dependency-of:gamma->alpha",
				"contains:alpha->" + lockName,
				"contains:" + lockName + "->beta",
				"evident-by:alpha->" + lockName,
				"evident-by:alpha->" + metadataName,
			}
			for _, key := range expected {
				_, ok := edges[key]
				assert.True(t, ok, "missing %s on SPDX %s", key, version)
			}

			primary := edges["evident-by:alpha->"+lockName]
			supporting := edges["evident-by:alpha->"+metadataName]
			require.Equal(t, map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}, primary.Data)
			require.Equal(t, map[string]string{"kind": pkg.SupportingEvidenceAnnotation}, supporting.Data)
		})
	}
}

func spdxJSONEndpointName(identifiable artifact.Identifiable) string {
	switch value := identifiable.(type) {
	case pkg.Package:
		return value.Name
	case file.Coordinates:
		return trimLeadingSlash(value.RealPath)
	case file.Location:
		return trimLeadingSlash(value.RealPath)
	default:
		return string(identifiable.ID())
	}
}

func trimLeadingSlash(path string) string {
	if len(path) > 0 && path[0] == '/' {
		return path[1:]
	}
	return path
}
