package spdxhelpers

import (
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// evidentByComment renders the OTHER relationship comment for an EvidentBy edge. SPDX has no native
// EvidentBy relationship, so the edge is carried as OTHER with this structured, reversible comment.
// The evidence kind (primary or supporting, from the location annotation) is appended as an
// explicit marker so it survives both SPDX 2.x and 3.0 round trips; an absent kind defaults to
// supporting to match internal/relationship.EvidentBy.
func evidentByComment(r artifact.Relationship) string {
	comment := string(artifact.EvidentByRelationship) + ": indicates the package's existence is evident by the given file"
	comment += "; evidence:" + evidentByKind(r)
	return comment
}

// evidentByKind mirrors internal/relationship.EvidentBy: an edge without a known annotation is
// treated as supporting evidence.
func evidentByKind(r artifact.Relationship) string {
	if kind := evidenceKind(r); kind != "" {
		return kind
	}
	return pkg.SupportingEvidenceAnnotation
}

// evidentByData parses an EvidentBy OTHER relationship comment back into the relationship Data.
// Comments without an explicit evidence marker still decode, recovering the edge even when the
// document was produced by a writer that did not know about the evidence category.
func evidentByData(comment string) map[string]string {
	kind := pkg.SupportingEvidenceAnnotation
	if _, value, ok := strings.Cut(comment, "; evidence:"); ok {
		value = strings.TrimSpace(strings.Split(value, ";")[0])
		if value == pkg.PrimaryEvidenceAnnotation || value == pkg.SupportingEvidenceAnnotation {
			kind = value
		}
	}
	return map[string]string{"kind": kind}
}

func evidenceKind(r artifact.Relationship) string {
	data, ok := r.Data.(map[string]string)
	if !ok {
		return ""
	}
	switch data["kind"] {
	case pkg.PrimaryEvidenceAnnotation, pkg.SupportingEvidenceAnnotation:
		return data["kind"]
	default:
		return ""
	}
}
