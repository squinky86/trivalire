package pixi

import (
	"context"
	"os"
	"path/filepath"

	parser "github.com/aquasecurity/trivy/pkg/dependency/parser/conda/pixi"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() { analyzer.RegisterAnalyzer(&pixiAnalyzer{}) }

type pixiAnalyzer struct{}

func (a pixiAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	apps, err := parser.Parse(ctx, input.FilePath, input.Content)
	if err != nil {
		log.WithPrefix("pixi").Warn("Incomplete Pixi inventory: unable to read lockfile", log.FilePath(input.FilePath), log.Err(err))
		return nil, err
	}
	return &analyzer.AnalysisResult{Applications: apps}, nil
}
func (a pixiAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.PixiLock
}
func (a pixiAnalyzer) Type() analyzer.Type { return analyzer.TypePixi }
func (a pixiAnalyzer) Version() int        { return 1 }
