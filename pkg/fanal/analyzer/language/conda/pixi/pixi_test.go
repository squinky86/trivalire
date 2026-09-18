package pixi

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func TestAnalyzer(t *testing.T) {
	a := pixiAnalyzer{}
	assert.Equal(t, analyzer.TypePixi, a.Type())
	assert.Equal(t, 1, a.Version())
	for _, name := range []string{"pixi.lock", "nested/pixi.lock"} {
		assert.True(t, a.Required(name, nil))
	}
	for _, name := range []string{"pixi.toml", "pyproject.toml", "pixi.lock.bak", "notpixi.lock"} {
		assert.False(t, a.Required(name, nil))
	}
	b, err := os.ReadFile("../../../../../dependency/parser/conda/pixi/testdata/pixi.lock")
	require.NoError(t, err)
	res, err := a.Analyze(t.Context(), analyzer.AnalysisInput{FilePath: "pixi.lock", Content: strings.NewReader(string(b))})
	require.NoError(t, err)
	require.Len(t, res.Applications, 3)
	_, err = a.Analyze(t.Context(), analyzer.AnalysisInput{FilePath: "pixi.lock", Content: strings.NewReader("version: 999")})
	require.Error(t, err)
}
