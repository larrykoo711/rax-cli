package cli

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const releaseRepo = "larrykoo711/rax-cli"

type ghRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (a App) runUpgrade(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rax upgrade", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	var checkOnly bool
	fs.BoolVar(&checkOnly, "check", false, "Only check if a newer version is available")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	client := &http.Client{Timeout: 30 * time.Second}
	rel, err := fetchLatestRelease(ctx, client)
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error checking latest release: %v\n", err)
		return 1
	}

	current := strings.TrimPrefix(a.Version, "v")
	latest := strings.TrimPrefix(rel.TagName, "v")
	if current == latest {
		fmt.Fprintf(a.Stdout, "rax %s is already up to date.\n", current)
		return 0
	}

	fmt.Fprintf(a.Stdout, "New version available: %s -> %s (%s)\n", current, latest, rel.HTMLURL)
	if checkOnly {
		return 0
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error locating current binary: %v\n", err)
		return 1
	}
	resolvedExe, _ := filepath.EvalSymlinks(exePath)
	if resolvedExe == "" {
		resolvedExe = exePath
	}

	if isHomebrewPath(resolvedExe) {
		fmt.Fprintf(a.Stdout, "Detected Homebrew installation (%s).\nRun:\n  brew upgrade larrykoo711/tap/rax\n", resolvedExe)
		return 0
	}

	assetName := fmt.Sprintf("rax-%s-%s-%s.tar.gz", rel.TagName, runtime.GOOS, runtime.GOARCH)
	var tarballURL, checksumsURL string
	for _, asset := range rel.Assets {
		if asset.Name == assetName {
			tarballURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			checksumsURL = asset.BrowserDownloadURL
		}
	}
	if tarballURL == "" || checksumsURL == "" {
		fmt.Fprintf(a.Stderr, "Error: release %s is missing asset %s or checksums.txt\n", rel.TagName, assetName)
		return 1
	}

	fmt.Fprintf(a.Stderr, "Downloading %s...\n", assetName)
	tarBytes, err := downloadBytes(ctx, client, tarballURL)
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error downloading tarball: %v\n", err)
		return 1
	}
	checksumBytes, err := downloadBytes(ctx, client, checksumsURL)
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error downloading checksums: %v\n", err)
		return 1
	}

	expectedHex, err := findChecksum(checksumBytes, assetName)
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error verifying checksum: %v\n", err)
		return 1
	}
	actualSum := sha256.Sum256(tarBytes)
	actualHex := hex.EncodeToString(actualSum[:])
	if !strings.EqualFold(actualHex, expectedHex) {
		fmt.Fprintf(a.Stderr, "Error: SHA-256 mismatch (expected %s, got %s)\n", expectedHex, actualHex)
		return 1
	}

	binBytes, err := extractBinaryFromTarGz(tarBytes, "rax")
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error extracting binary: %v\n", err)
		return 1
	}

	tmpPath := resolvedExe + ".upgrade.tmp"
	if err := os.WriteFile(tmpPath, binBytes, 0o755); err != nil {
		fmt.Fprintf(a.Stderr, "Error writing upgraded binary (check write permissions on %s): %v\n", filepath.Dir(resolvedExe), err)
		return 1
	}
	if err := os.Rename(tmpPath, resolvedExe); err != nil {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(a.Stderr, "Error replacing binary: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.Stdout, "Upgraded rax to %s.\n", latest)
	return 0
}

func isHomebrewPath(p string) bool {
	return strings.Contains(p, "/Cellar/") || strings.Contains(p, "/homebrew/") || strings.Contains(p, "/linuxbrew/")
}

func fetchLatestRelease(ctx context.Context, client *http.Client) (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", releaseRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "rax-cli")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("empty release tag")
	}
	return &rel, nil
}

func downloadBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rax-cli")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 50<<20))
}

func findChecksum(raw []byte, filename string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && strings.TrimPrefix(fields[1], "*") == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum entry for %s not found", filename)
}

func extractBinaryFromTarGz(raw []byte, target string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == target && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 50<<20))
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", target)
}
