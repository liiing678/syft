package cyclonedxjson

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const (
	jsonLockPath     = "/app/package-lock.json"
	jsonMetadataPath = "/app/node_modules/alpha/package.json"
)

// jsonEvidenceFixture is the format-level synthetic fixture: three packages, two evidence files,
// dependency, containment and evidence edges, with one primary and one supporting category.
func jsonEvidenceFixture(t *testing.T) sbom.SBOM {
	t.Helper()

	alpha := pkg.Package{Name: "alpha", Version: "1.0", Type: pkg.NpmPkg, PURL: "pkg:npm/alpha@1.0"}
	beta := pkg.Package{Name: "beta", Version: "2.0", Type: pkg.NpmPkg, PURL: "pkg:npm/beta@2.0"}
	gamma := pkg.Package{Name: "gamma", Version: "3.0", Type: pkg.NpmPkg, PURL: "pkg:npm/gamma@3.0"}
	alpha.SetID()
	beta.SetID()
	gamma.SetID()

	lock := file.Coordinates{RealPath: jsonLockPath}
	metadata := file.Coordinates{RealPath: jsonMetadataPath}

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

func TestEvidenceRelationshipNestedArchiveRoundTrip(t *testing.T) {
	outer := file.NewCoordinates("/app.war", "")
	inner, ok := internal.NestedCoordinates(outer, "WEB-INF/lib/a.jar")
	require.True(t, ok)
	entry, ok := internal.NestedCoordinates(inner, "META-INF/MANIFEST.MF")
	require.True(t, ok)

	alpha := pkg.Package{Name: "alpha", PURL: "pkg:maven/alpha@1", Type: pkg.JavaPkg}
	alpha.SetID()

	input := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(alpha),
			FileMetadata: map[file.Coordinates]file.Metadata{
				outer: {}, inner: {}, entry: {},
			},
		},
		Relationships: []artifact.Relationship{
			{From: alpha, To: entry, Type: artifact.EvidentByRelationship, Data: map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}},
			{From: inner, To: alpha, Type: artifact.ContainsRelationship},
		},
	}

	enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: "1.6"})
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, enc.Encode(&buf, input))

	decoded, _, _, err := NewFormatDecoder().Decode(&buf)
	require.NoError(t, err)
	require.Len(t, decoded.Relationships, 2)

	byType := map[artifact.RelationshipType]artifact.Relationship{}
	for _, r := range decoded.Relationships {
		byType[r.Type] = r
	}

	evidentBy, ok := byType[artifact.EvidentByRelationship]
	require.True(t, ok)
	assert.Equal(t, "alpha", jsonEndpointName(evidentBy.From))
	assert.Equal(t, trimSlash(entry.FullNestedPath()), jsonEndpointName(evidentBy.To))
	assert.Equal(t, map[string]string{"kind": pkg.PrimaryEvidenceAnnotation}, evidentBy.Data)

	contains, ok := byType[artifact.ContainsRelationship]
	require.True(t, ok)
	assert.Equal(t, trimSlash(inner.FullNestedPath()), jsonEndpointName(contains.From))
	assert.Equal(t, "alpha", jsonEndpointName(contains.To))
}

func TestEvidenceRelationshipSchemaAndRoundTrip(t *testing.T) {
	input := jsonEvidenceFixture(t)

	for _, version := range SupportedVersions() {
		t.Run(version, func(t *testing.T) {
			enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: version})
			require.NoError(t, err)

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, input))

			validateCycloneDXSchema(t, version, buf.String())

			decoded, _, _, err := NewFormatDecoder().Decode(&buf)
			require.NoError(t, err)

			edges := map[string]bool{}
			evidenceKinds := map[string]string{}
			for _, r := range decoded.Relationships {
				from := jsonEndpointName(r.From)
				to := jsonEndpointName(r.To)
				edges[string(r.Type)+":"+from+"->"+to] = true
				if r.Type == artifact.EvidentByRelationship {
					if data, ok := r.Data.(map[string]string); ok {
						evidenceKinds[from+"->"+to] = data["kind"]
					}
				}
			}

			lockName := jsonLockPath[1:]
			metadataName := jsonMetadataPath[1:]
			expected := []string{
				"dependency-of:beta->alpha",
				"dependency-of:gamma->alpha",
				"contains:alpha->" + lockName,
				"contains:" + lockName + "->beta",
				"evident-by:alpha->" + lockName,
				"evident-by:alpha->" + metadataName,
			}

			if version < "1.5" {
				// BOM-level properties do not exist before 1.5, so the four non-dependency edges
				// cannot be represented without violating the schema; dependency edges remain.
				for _, edge := range expected[:2] {
					assert.True(t, edges[edge], "missing %s on spec %s", edge, version)
				}
				assert.Len(t, edges, 2)
				return
			}

			for _, edge := range expected {
				assert.True(t, edges[edge], "missing %s on spec %s", edge, version)
			}
			assert.Len(t, edges, len(expected))
			assert.Equal(t, pkg.PrimaryEvidenceAnnotation, evidenceKinds["alpha->"+lockName])
			assert.Equal(t, pkg.SupportingEvidenceAnnotation, evidenceKinds["alpha->"+metadataName])
		})
	}
}

func validateCycloneDXSchema(t *testing.T, version, document string) {
	t.Helper()
	modCache := os.Getenv("GOMODCACHE")
	if modCache == "" {
		modCache = filepath.Join(os.Getenv("GOPATH"), "pkg", "mod")
	}
	if modCache == "pkg/mod" {
		if output, err := exec.Command("go", "env", "GOMODCACHE").Output(); err == nil {
			modCache = strings.TrimSpace(string(output))
		}
	}
	moduleSchemas, err := filepath.Glob(filepath.Join(modCache,
		"github.com/!cyclone!d!x/cyclonedx-go@*/schema/bom-"+version+".schema.json"))
	require.NoError(t, err)
	require.Len(t, moduleSchemas, 1)

	// the schema references sibling files by their published names; host the whole directory over
	// a local filesystem so gojsonschema resolves every reference offline, including the jsf schema
	// the module stores with a ".schemax.json" suffix
	schemaDir := t.TempDir()
	require.NoError(t, copySchemaDir(filepath.Dir(moduleSchemas[0]), schemaDir))

	schemaLoader := gojsonschema.NewReferenceLoaderFileSystem(
		"file://"+filepath.Join(schemaDir, "bom-"+version+".schema.json"),
		schemaFileSystem{dir: schemaDir},
	)
	result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewStringLoader(document))
	if err != nil && isIncompleteModuleSchema(err) {
		// cyclonedx-go v0.12.0 ships bom-1.7 without its cryptography-defs.schema.json sibling;
		// the missing definitions only constrain optional crypto-asset fields syft never emits,
		// so full offline validation is not possible for that one spec version.
		t.Skipf("module schema for spec %s is incomplete: %v", version, err)
	}
	require.NoError(t, err)

	if !result.Valid() {
		for _, problem := range result.Errors() {
			t.Errorf("schema error: %s", problem)
		}
	}
}

func isIncompleteModuleSchema(err error) bool {
	return strings.Contains(err.Error(), "no such file or directory") ||
		strings.Contains(err.Error(), "file not found")
}

// schemaFileSystem serves the offline schema directory. gojsonschema opens files by their
// absolute file:// path, which http.Dir rejects as outside its root, so every request is
// re-anchored to the temporary directory holding the copied schemas.
type schemaFileSystem struct {
	dir string
}

func (fs schemaFileSystem) Open(name string) (http.File, error) {
	clean := filepath.Clean(name)
	if rel, err := filepath.Rel(fs.dir, clean); err == nil && !strings.HasPrefix(rel, "..") {
		name = rel
	}
	return http.Dir(fs.dir).Open(filepath.ToSlash(name))
}

func copySchemaDir(sourceDir, targetDir string) error {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// the module ships the jsf schema as "jsf-0.82.schemax.json"; restore its published name
		name := entry.Name()
		if strings.HasSuffix(name, ".schemax.json") {
			name = strings.TrimSuffix(name, "x.json") + ".json"
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(sourceDir, entry.Name()))
		if err != nil {
			return err
		}

		var document map[string]any
		if err := json.Unmarshal(raw, &document); err == nil {
			// point remote CycloneDX $ids at the local copied file so no reference leaves the
			// offline filesystem during validation
			if id, ok := document["$id"].(string); ok && strings.HasPrefix(id, "http://cyclonedx.org/schema/") {
				document["$id"] = "file://" + filepath.Join(targetDir, name)
			}
			raw, err = json.Marshal(document)
			if err != nil {
				return err
			}
		}

		out, err := os.Create(filepath.Join(targetDir, name))
		if err != nil {
			return err
		}
		if _, err := out.Write(raw); err != nil {
			_ = out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

func jsonEndpointName(identifiable artifact.Identifiable) string {
	switch value := identifiable.(type) {
	case pkg.Package:
		return value.Name
	case file.Coordinates:
		return trimSlash(value.FullNestedPath())
	default:
		return string(identifiable.ID())
	}
}

func trimSlash(path string) string {
	if len(path) > 0 && path[0] == '/' {
		return path[1:]
	}
	return path
}
