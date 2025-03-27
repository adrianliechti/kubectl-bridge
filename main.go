package main

import (
	"embed"
	"os"
	"path/filepath"

	"github.com/adrianliechti/kubectl-bridge/pkg/server"
)

var (
	//go:embed public
	public embed.FS
)

func main() {
	dir, err := os.MkdirTemp("", "bridge")

	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)

	if err := os.CopyFS(dir, public); err != nil {
		panic(err)
	}

	if err := os.Chdir(filepath.Join(dir, "public")); err != nil {
		panic(err)
	}

	s, err := server.New()

	if err != nil {
		panic(err)
	}

	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}
