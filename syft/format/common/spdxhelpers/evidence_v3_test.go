package spdxhelpers

import (
	"testing"

	spdx "github.com/spdx/tools-golang/spdx/v3/v3_0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func TestToSyftModelV3_evidentByKeepsEvidenceKind(t *testing.T) {
	packageElement := &spdx.Package{
		ID:   "package-alpha",
		Name: "alpha",
		ExternalIdentifiers: spdx.ExternalIdentifierList{
			&spdx.ExternalIdentifier{
				Type:       spdx.ExternalIdentifierType_PackageURL,
				Identifier: "pkg:npm/alpha@1.0",
			},
		},
	}
	lockFile := &spdx.File{ID: "file-lock", Name: "/app/package-lock.json"}

	primaryEvidence := &spdx.Relationship{
		From:    packageElement,
		To:      spdx.ElementList{lockFile},
		Type:    spdx.RelationshipType_Other,
		Comment: "evident-by: indicates the package's existence is evident by the given file; evidence:primary",
	}

	doc := &spdx.Document{
		SpdxDocument: spdx.SpdxDocument{
			ID:       "https://example.org/evidence-doc",
			Name:     "evidence-doc",
			Elements: spdx.ElementList{packageElement, lockFile, primaryEvidence},
		},
	}

	result, err := ToSyftModelV3(doc)
	require.NoError(t, err)

	var evidentBy []artifact.Relationship
	for _, r := range result.Relationships {
		if r.Type == artifact.EvidentByRelationship {
			evidentBy = append(evidentBy, r)
		}
	}
	require.Len(t, evidentBy, 1)

	from, ok := evidentBy[0].From.(pkg.Package)
	require.True(t, ok)
	assert.Equal(t, "alpha", from.Name)
	assert.Equal(t, map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}, evidentBy[0].Data)
}

func TestToSyftModelV3_legacyEvidentByCommentDefaultsToSupporting(t *testing.T) {
	packageElement := &spdx.Package{
		ID:   "package-beta",
		Name: "beta",
		ExternalIdentifiers: spdx.ExternalIdentifierList{
			&spdx.ExternalIdentifier{
				Type:       spdx.ExternalIdentifierType_PackageURL,
				Identifier: "pkg:npm/beta@2.0",
			},
		},
	}
	lockFile := &spdx.File{ID: "file-lock-legacy", Name: "/app/package-lock.json"}

	legacyEvidence := &spdx.Relationship{
		From:    packageElement,
		To:      spdx.ElementList{lockFile},
		Type:    spdx.RelationshipType_Other,
		Comment: "evident-by: indicates the package's existence is evident by the given file",
	}

	doc := &spdx.Document{
		SpdxDocument: spdx.SpdxDocument{
			ID:       "https://example.org/legacy-doc",
			Name:     "legacy-doc",
			Elements: spdx.ElementList{packageElement, lockFile, legacyEvidence},
		},
	}

	result, err := ToSyftModelV3(doc)
	require.NoError(t, err)

	var evidentBy []artifact.Relationship
	for _, r := range result.Relationships {
		if r.Type == artifact.EvidentByRelationship {
			evidentBy = append(evidentBy, r)
		}
	}
	require.Len(t, evidentBy, 1)
	assert.Equal(t, map[string]string{"kind": pkg.SupportingEvidenceAnnotation}, evidentBy[0].Data)
}
