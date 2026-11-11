package helpers

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/artifact"
)

// CycloneDX has no native relationship type for the syft Contains or EvidentBy edges, so they are
// recorded as namespaced BOM properties. Each edge is fully described by a fixed set of property
// names sharing an index, which keeps the encoding deterministic and reversible:
//
//	syft:relationship:<i>:type      contains | evident-by
//	syft:relationship:<i>:from      bom-ref of the source component
//	syft:relationship:<i>:to        bom-ref of the target component
//	syft:relationship:<i>:evidence  primary | supporting (evident-by only)
//
// BOM-level properties are valid from CycloneDX 1.5; earlier specs do not define them, in which
// case these edges cannot be carried without changing the document structure and are omitted.
const (
	relationshipPropertyPrefix = "syft:relationship:"

	relationshipTypeContains  = string(artifact.ContainsRelationship)
	relationshipTypeEvidentBy = string(artifact.EvidentByRelationship)

	evidenceKindPrimary    = "primary"
	evidenceKindSupporting = "supporting"
)

// EncodeRelationshipProperties renders the non-dependency syft relationships (Contains and
// EvidentBy) as deterministic BOM properties. DependencyOf edges stay in the native
// dependencies section and must not be duplicated here. bomRef maps each endpoint's syft ID to
// the bom-ref of the component that encodes it, since package bom-refs are derived from the PURL
// rather than being the raw syft ID.
func EncodeRelationshipProperties(relationships []artifact.Relationship, bomRef map[artifact.ID]string) []cyclonedx.Property {
	edges := make([]artifact.Relationship, 0, len(relationships))
	for _, r := range relationships {
		if r.Type != artifact.ContainsRelationship && r.Type != artifact.EvidentByRelationship {
			continue
		}
		if r.From == nil || r.To == nil {
			continue
		}
		if _, ok := bomRef[r.From.ID()]; !ok {
			continue
		}
		if _, ok := bomRef[r.To.ID()]; !ok {
			continue
		}
		edges = append(edges, r)
	}
	if len(edges) == 0 {
		return nil
	}

	sort.Slice(edges, func(i, j int) bool {
		return relationshipSortKey(edges[i]) < relationshipSortKey(edges[j])
	})

	var props []cyclonedx.Property
	for i, r := range edges {
		prefix := fmt.Sprintf("%s%d:", relationshipPropertyPrefix, i)
		props = append(props,
			cyclonedx.Property{Name: prefix + "type", Value: string(r.Type)},
			cyclonedx.Property{Name: prefix + "from", Value: bomRef[r.From.ID()]},
			cyclonedx.Property{Name: prefix + "to", Value: bomRef[r.To.ID()]},
		)
		if kind := evidenceKind(r); kind != "" {
			props = append(props, cyclonedx.Property{Name: prefix + "evidence", Value: kind})
		}
	}
	return props
}

func relationshipSortKey(r artifact.Relationship) string {
	return strings.Join([]string{string(r.Type), string(r.From.ID()), string(r.To.ID()), evidenceKind(r)}, "\x00")
}

// evidenceKind reads the "kind" entry produced by internal/relationship.EvidentBy. Empty means
// the edge predates the annotation data; the kind is then omitted rather than invented.
func evidenceKind(r artifact.Relationship) string {
	data, ok := r.Data.(map[string]string)
	if !ok {
		return ""
	}
	switch data["kind"] {
	case evidenceKindPrimary, evidenceKindSupporting:
		return data["kind"]
	default:
		return ""
	}
}

// DecodeRelationshipProperties reconstructs the relationships stored by
// EncodeRelationshipProperties. The idMap resolves bom-refs to the packages and file
// coordinates collected from the components; edges referencing unknown bom-refs are skipped
// rather than producing dangling pointers.
func DecodeRelationshipProperties(bom *cyclonedx.BOM, idMap map[string]any) []artifact.Relationship {
	if bom == nil || bom.Properties == nil {
		return nil
	}

	type edge struct {
		typ      string
		fromRef  string
		toRef    string
		evidence string
	}
	edges := map[int]*edge{}
	for _, p := range *bom.Properties {
		index, field, ok := parseRelationshipPropertyName(p.Name)
		if !ok {
			continue
		}
		e := edges[index]
		if e == nil {
			e = &edge{}
			edges[index] = e
		}
		switch field {
		case "type":
			e.typ = p.Value
		case "from":
			e.fromRef = p.Value
		case "to":
			e.toRef = p.Value
		case "evidence":
			e.evidence = p.Value
		}
	}

	indexes := make([]int, 0, len(edges))
	for index := range edges {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)

	var out []artifact.Relationship
	for _, index := range indexes {
		e := edges[index]
		if e.typ != relationshipTypeContains && e.typ != relationshipTypeEvidentBy {
			continue
		}
		from, fromOk := resolveRelationshipEndpoint(idMap, e.fromRef)
		to, toOk := resolveRelationshipEndpoint(idMap, e.toRef)
		if !fromOk || !toOk {
			continue
		}
		r := artifact.Relationship{
			From: from,
			To:   to,
			Type: artifact.RelationshipType(e.typ),
		}
		if e.typ == relationshipTypeEvidentBy {
			kind := e.evidence
			if kind != evidenceKindPrimary && kind != evidenceKindSupporting {
				kind = evidenceKindSupporting
			}
			r.Data = map[string]string{"kind": kind}
		}
		out = append(out, r)
	}
	return out
}

func parseRelationshipPropertyName(name string) (index int, field string, ok bool) {
	rest, ok := strings.CutPrefix(name, relationshipPropertyPrefix)
	if !ok {
		return 0, "", false
	}
	indexPart, field, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, "", false
	}
	index, err := strconv.Atoi(indexPart)
	if err != nil || index < 0 {
		return 0, "", false
	}
	return index, field, true
}

func resolveRelationshipEndpoint(idMap map[string]any, ref string) (artifact.Identifiable, bool) {
	endpoint, ok := idMap[ref]
	if !ok {
		return nil, false
	}
	identifiable, ok := PtrToStruct(endpoint).(artifact.Identifiable)
	if !ok {
		return nil, false
	}
	return identifiable, true
}
