package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	core "github.com/filecoin-project/go-indexer-core"
	"github.com/filecoin-project/go-indexer-core/store"
	"github.com/filecoin-project/go-indexer-core/store/persistent/pogreb"
	"github.com/filecoin-project/go-indexer-core/store/persistent/storethehash"
	"github.com/filecoin-project/go-indexer-core/store/primary"
	logging "github.com/ipfs/go-log/v2"
	"github.com/mitchellh/go-homedir"
	"github.com/urfave/cli/v2"
)

var log = logging.Logger("node")

const defaultStorageDir = ".storetheindex"

type Node struct {
	storage store.Storage
	api     *api
}

func New(cctx *cli.Context) (*Node, error) {
	n := new(Node)
	var prim store.Storage
	var pers store.PersistentStorage

	cacheSize := int(cctx.Int64("cachesize"))
	if cacheSize != 0 {
		prim = primary.New(cacheSize)
		log.Infow("cache enabled", "size", cacheSize)
	} else {
		log.Info("cache disabled")
	}

	switch storageType := cctx.String("storage"); storageType {
	case "none":
		if prim == nil {
			return nil, errors.New("cache and storage cannot both be disabled")
		}
		log.Info("persistent storage disabled")

	case "sth", "prgreb":
		storageDir, err := checkStorageDir(cctx.String("dir"))
		if err != nil {
			return nil, err
		}

		if storageType == "sth" {
			pers, err = storethehash.New(storageDir)
		} else {
			pers, err = pogreb.New(storageDir)
		}
		if err != nil {
			return nil, err
		}

		log.Infow("Persistent storage enabled", "type", storageType, "dir", storageDir)

	default:
		return nil, fmt.Errorf("unrecognized storage type: %s", storageType)
	}

	n.storage = core.NewStorage(prim, pers)
	err := n.initAPI(cctx.String("endpoint"))
	if err != nil {
		return nil, err
	}

	return n, nil
}

func (n *Node) Start() error {
	log.Info("Started server")
	// TODO: Start required processes for stores
	return n.api.Serve()

}

func (n *Node) Shutdown(ctx context.Context) error {
	return n.api.Shutdown(ctx)
}

func checkStorageDir(dir string) (string, error) {
	var err error
	if dir != "" {
		dir, err = homedir.Expand(dir)
		if err != nil {
			return "", err
		}
	} else {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		if home == "" {
			return "", errors.New("could not determine storage directory, home dir not set")
		}

		dir = filepath.Join(home, defaultStorageDir)
	}

	if err = checkMkDir(dir); err != nil {
		return "", err
	}

	return dir, nil
}

// checkMkDir checks that the directory exists, and if not, creates it
func checkMkDir(dir string) error {
	_, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if err = os.Mkdir(dir, 0644); err != nil {
				return err
			}
			return nil
		}
		return err
	}
	return nil
}
