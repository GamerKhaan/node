package distributionguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestForkDistribution(t *testing.T) {
	release := read(t, ".github/workflows/docker-build.yml")
	dev := read(t, ".github/workflows/docker-build-dev.yml")
	dockerfile := read(t, "Dockerfile")
	for name, text := range map[string]string{"release": release, "dev": dev} {
		if !strings.Contains(text, "IMAGE_NAME: ghcr.io/gamerkhaan/node") {
			t.Fatalf("%s workflow missing owned image", name)
		}
		if strings.Contains(text, "DOCKERHUB_") || strings.Contains(text, "ghcr.io/pasarguard/") || strings.Contains(text, "pasarguard/${{") {
			t.Fatalf("%s workflow still publishes upstream namespace", name)
		}
	}
	if !strings.Contains(dockerfile, `org.opencontainers.image.source="https://github.com/GamerKhaan/node"`) {
		t.Fatal("Dockerfile source label is not fork-owned")
	}
}
