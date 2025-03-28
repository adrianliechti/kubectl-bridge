package main

import (
	"os"

	"github.com/adrianliechti/kubectl-bridge/pkg/public"
	"github.com/adrianliechti/kubectl-bridge/pkg/server"
)

func main() {
	dir, err := os.MkdirTemp("", "bridge")

	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)

	if err := public.CopyFS(dir); err != nil {
		panic(err)
	}

	if err := os.Chdir(dir); err != nil {
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
