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
	dockerfileXray := read(t, "Dockerfile.xray")
	dockerfileWireGuard := read(t, "Dockerfile.wireguard")
	makefile := read(t, "Makefile")
	controller := read(t, "controller/controller.go")
	releaseAssets := read(t, ".github/workflows/release.yml")
	for name, text := range map[string]string{"release": release, "dev": dev} {
		if !strings.Contains(text, "IMAGE_NAME: ghcr.io/gamerkhaan/node") {
			t.Fatalf("%s workflow missing owned image", name)
		}
		if strings.Contains(text, "DOCKERHUB_") || strings.Contains(text, "ghcr.io/pasarguard/") || strings.Contains(text, "pasarguard/${{") {
			t.Fatalf("%s workflow still publishes upstream namespace", name)
		}
	}
	for name, text := range map[string]string{"Dockerfile": dockerfile, "Dockerfile.xray": dockerfileXray, "Dockerfile.wireguard": dockerfileWireGuard} {
		if !strings.Contains(text, `org.opencontainers.image.source="https://github.com/GamerKhaan/node"`) {
			t.Fatalf("%s source label is not fork-owned", name)
		}
	}
	if strings.Contains(makefile, "github.com/PasarGuard/scripts/raw/main/install_core.sh") {
		t.Fatal("Makefile still installs core from upstream scripts")
	}
	if !strings.Contains(makefile, "github.com/GamerKhaan/scripts/raw/main/install_core.sh") {
		t.Fatal("Makefile does not install core from owned scripts")
	}
	if !strings.Contains(controller, `const NodeVersion = "0.5.4-awg31.1"`) {
		t.Fatal("Node runtime version does not identify the owned release")
	}
	if strings.Contains(releaseAssets, "openbsd") {
		t.Fatal("owned Node binary release still targets unsupported OpenBSD")
	}
	if !strings.Contains(releaseAssets, "linux") || !strings.Contains(releaseAssets, "arm64") || !strings.Contains(releaseAssets, "amd64") {
		t.Fatal("owned Node binary release must cover Linux amd64/arm64")
	}
	if strings.Contains(releaseAssets, "actions/upload-release-asset@v1") {
		t.Fatal("owned Node release must not depend on deprecated upload-release-asset action")
	}
	if !strings.Contains(releaseAssets, "gh release upload") {
		t.Fatal("owned Node release must upload assets through gh CLI")
	}
	if !strings.Contains(releaseAssets, "ref: ${{ github.event.release.tag_name || inputs.tag }}") {
		t.Fatal("manual Node release must build the exact requested release tag")
	}
}
