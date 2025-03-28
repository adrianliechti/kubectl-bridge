package public

import (
	"embed"
	"os"
)

var (
	//go:embed pkg
	//go:embed static
	fs embed.FS
)

func CopyFS(dir string) error {
	if err := os.CopyFS(dir, fs); err != nil {
		return err
	}

	return nil
}
