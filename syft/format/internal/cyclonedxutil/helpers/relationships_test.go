package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func evidenceFixture() (pkg.Package, pkg.Package, pkg.Package, file.Coordinates, file.Coordinates) {
	alpha := pkg.Package{Name: "alpha", Version: "1.0", Type: pkg.NpmPkg, PURL: "pkg:npm/alpha@1.0"}
	beta := pkg.Package{Name: "beta", Version: "2.0", Type: pkg.NpmPkg, PURL: "pkg:npm/beta@2.0"}
	gamma := pkg.Package{Name: "gamma", Version: "3.0", Type: pkg.NpmPkg, PURL: "pkg:npm/gamma@3.0"}
	alpha.SetID()
	beta.SetID()
	gamma.SetID()

	lock := file.Coordinates{RealPath: "/app/package-lock.json"}
	metadata := file.Coordinates{RealPath: "/app/node_modules/alpha/package.json"}
	return alpha, beta, gamma, lock, metadata
}

func TestEncodeRelationshipProperties(t *testing.T) {
	alpha, beta, _, lock, metadata := evidenceFixture()

	relationships := []artifact.Relationship{
		// dependency edges are never duplicated into the properties
		{From: beta, To: alpha, Type: artifact.DependencyOfRelationship},
		// edges without resolvable bom-refs are skipped rather than dangling
		{From: alpha, To: file.Coordinates{RealPath: "/missing.txt"}, Type: artifact.ContainsRelationship},
		{From: alpha, To: lock, Type: artifact.ContainsRelationship},
		{From: lock, To: beta, Type: artifact.ContainsRelationship},
		{From: alpha, To: lock, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": "primary"}},
		{From: alpha, To: metadata, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": "supporting"}},
		{From: beta, To: metadata, Type: artifact.EvidentByRelationship},
	}

	bomRefs := map[artifact.ID]string{
		alpha.ID():    DeriveBomRef(alpha),
		beta.ID():     DeriveBomRef(beta),
		lock.ID():     string(lock.ID()),
		metadata.ID(): string(metadata.ID()),
	}

	props := EncodeRelationshipProperties(relationships, bomRefs)

	// five resolvable edges: two contains and three evident-by; the dangling edge and the
	// dependency-of edge never appear. Two evident-by edges carry a kind, one does not.
	require.Len(t, props, 5*3+2)

	byIndex := map[int]map[string]string{}
	for _, p := range props {
		index, field, ok := parseRelationshipPropertyName(p.Name)
		require.True(t, ok)
		if byIndex[index] == nil {
			byIndex[index] = map[string]string{}
		}
		byIndex[index][field] = p.Value
	}
	require.Len(t, byIndex, 5)

	expectedEdges := map[string]map[string]string{
		"contains|" + string(lock.ID()) + "->" + DeriveBomRef(beta): {
			"type": "contains", "from": string(lock.ID()), "to": DeriveBomRef(beta),
		},
		"contains|" + DeriveBomRef(alpha) + "->" + string(lock.ID()): {
			"type": "contains", "from": DeriveBomRef(alpha), "to": string(lock.ID()),
		},
		"evident-by|" + DeriveBomRef(alpha) + "->" + string(lock.ID()): {
			"type": "evident-by", "from": DeriveBomRef(alpha), "to": string(lock.ID()), "evidence": "primary",
		},
		"evident-by|" + DeriveBomRef(alpha) + "->" + string(metadata.ID()): {
			"type": "evident-by", "from": DeriveBomRef(alpha), "to": string(metadata.ID()), "evidence": "supporting",
		},
		"evident-by|" + DeriveBomRef(beta) + "->" + string(metadata.ID()): {
			"type": "evident-by", "from": DeriveBomRef(beta), "to": string(metadata.ID()),
		},
	}
	actualEdges := map[string]map[string]string{}
	for _, edge := range byIndex {
		key := edge["type"] + "|" + edge["from"] + "->" + edge["to"]
		actualEdges[key] = edge
	}
	for key, expected := range expectedEdges {
		actual, ok := actualEdges[key]
		require.True(t, ok, "missing edge %s", key)
		for field, value := range expected {
			assert.Equal(t, value, actual[field], "edge %s field %s", key, field)
		}
	}

	// indices must be a dense 0..n sequence so consumers can iterate deterministically
	for i := range 5 {
		assert.Contains(t, byIndex, i)
	}

	t.Run("nil without non-dependency edges", func(t *testing.T) {
		assert.Nil(t, EncodeRelationshipProperties(
			[]artifact.Relationship{{From: beta, To: alpha, Type: artifact.DependencyOfRelationship}},
			bomRefs,
		))
	})
}

func TestDecodeRelationshipProperties(t *testing.T) {
	alpha, beta, _, lock, metadata := evidenceFixture()

	props := []cyclonedx.Property{
		{Name: "syft:relationship:0:type", Value: "contains"},
		{Name: "syft:relationship:0:from", Value: string(lock.ID())},
		{Name: "syft:relationship:0:to", Value: DeriveBomRef(beta)},
		{Name: "syft:relationship:1:type", Value: "evident-by"},
		{Name: "syft:relationship:1:from", Value: DeriveBomRef(alpha)},
		{Name: "syft:relationship:1:to", Value: string(lock.ID())},
		{Name: "syft:relationship:1:evidence", Value: "primary"},
		{Name: "syft:relationship:2:type", Value: "evident-by"},
		{Name: "syft:relationship:2:from", Value: DeriveBomRef(alpha)},
		{Name: "syft:relationship:2:to", Value: string(metadata.ID())},
		// an edge produced before evidence categories existed: recovered with the supporting default
		{Name: "syft:relationship:3:type", Value: "evident-by"},
		{Name: "syft:relationship:3:from", Value: DeriveBomRef(beta)},
		{Name: "syft:relationship:3:to", Value: string(metadata.ID())},
		// unknown and malformed properties must not break decoding
		{Name: "syft:relationship:other:type", Value: "contains"},
		{Name: "syft:package:type", Value: "npm"},
		{Name: "syft:relationship:4:type", Value: "evident-by"},
		{Name: "syft:relationship:4:from", Value: "missing-bom-ref"},
		{Name: "syft:relationship:4:to", Value: string(metadata.ID())},
	}

	idMap := map[string]any{
		DeriveBomRef(alpha):   alpha,
		DeriveBomRef(beta):    beta,
		string(alpha.ID()):    alpha,
		string(beta.ID()):     beta,
		string(lock.ID()):     lock,
		string(metadata.ID()): metadata,
	}

	bom := &cyclonedx.BOM{Properties: &props}
	got := DecodeRelationshipProperties(bom, idMap)

	require.Len(t, got, 4)

	assert.Equal(t, lock, got[0].From)
	assert.Equal(t, beta, got[0].To)
	assert.Equal(t, artifact.ContainsRelationship, got[0].Type)
	assert.Nil(t, got[0].Data)

	kindByEndpoint := map[string]map[string]string{}
	for _, r := range got[1:] {
		require.Equal(t, artifact.EvidentByRelationship, r.Type)
		kindByEndpoint[string(r.From.ID())+"->"+string(r.To.ID())] = r.Data.(map[string]string)
	}
	assert.Equal(t, map[string]string{"kind": "primary"},
		kindByEndpoint[string(alpha.ID())+"->"+string(lock.ID())])
	assert.Equal(t, map[string]string{"kind": "supporting"},
		kindByEndpoint[string(alpha.ID())+"->"+string(metadata.ID())])
	assert.Equal(t, map[string]string{"kind": "supporting"},
		kindByEndpoint[string(beta.ID())+"->"+string(metadata.ID())])

	t.Run("nil without properties", func(t *testing.T) {
		assert.Nil(t, DecodeRelationshipProperties(&cyclonedx.BOM{}, idMap))
		assert.Nil(t, DecodeRelationshipProperties(nil, idMap))
	})
}

func TestDedupeRelationships(t *testing.T) {
	alpha, beta, _, lock, _ := evidenceFixture()

	in := []artifact.Relationship{
		{From: beta, To: alpha, Type: artifact.DependencyOfRelationship},
		// the same edge encoded natively and as a property
		{From: beta, To: alpha, Type: artifact.DependencyOfRelationship},
		// a different type between the same endpoints is a distinct edge
		{From: beta, To: alpha, Type: artifact.ContainsRelationship},
		{From: alpha, To: lock, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": "primary"}},
		{From: alpha, To: lock, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": "primary"}},
	}

	got := dedupeRelationships(in)
	require.Len(t, got, 3)

	keys := map[string]bool{}
	for _, r := range got {
		keys[string(r.Type)+"|"+string(r.From.ID())+"|"+string(r.To.ID())] = true
	}
	assert.True(t, keys["dependency-of|"+string(beta.ID())+"|"+string(alpha.ID())])
	assert.True(t, keys["contains|"+string(beta.ID())+"|"+string(alpha.ID())])
	assert.True(t, keys["evident-by|"+string(alpha.ID())+"|"+string(lock.ID())])
}
