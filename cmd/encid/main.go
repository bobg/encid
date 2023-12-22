package main

import (
	"context"
	"crypto/aes"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/bobg/subcmd/v2"
	"github.com/pkg/errors"

	"github.com/bobg/encid"
	"github.com/bobg/encid/sqlite"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ksfile, err := os.UserConfigDir()
	if err != nil {
		return errors.Wrap(err, "getting user config dir")
	}
	ksfile = filepath.Join(ksfile, "encid", "keystore.db")

	flag.StringVar(&ksfile, "keystore", ksfile, "pathname of keystore")
	flag.Parse()

	ksdir := filepath.Dir(ksfile)
	if err := os.MkdirAll(ksdir, 0700); err != nil {
		return errors.Wrapf(err, "creating directory %s", ksdir)
	}

	ctx := context.Background()

	ks, err := sqlite.New(ksfile, aes.NewCipher)
	if err != nil {
		return errors.Wrapf(err, "opening %s", ksfile)
	}

	c := maincmd{ks: ks}

	return subcmd.Run(ctx, c, flag.Args())
}

type maincmd struct {
	ks *sqlite.KeyStore
}

func (c maincmd) Subcmds() subcmd.Map {
	return subcmd.Commands(
		"enc", c.doEnc, "encode a number", subcmd.Params(
			"-50", subcmd.Bool, false, "use base50",
			"typ", subcmd.Int, 0, "type of number to encode",
			"n", subcmd.Int64, 0, "number to encode",
		),
		"dec", c.doDec, "decode a number", subcmd.Params(
			"-50", subcmd.Bool, false, "use base50",
			"id", subcmd.Int64, 0, "id of decoding key",
			"inp", subcmd.String, "", "input string to decode",
		),
		"newkey", c.doNewKey, "create a new key", subcmd.Params(
			"typ", subcmd.Int, 0, "type of key to creae",
		),
	)
}

func (c maincmd) doEnc(ctx context.Context, fifty bool, typ int, n int64, _ []string) error {
	return c.tryEnc(ctx, fifty, typ, n, false)
}

func (c maincmd) tryEnc(ctx context.Context, fifty bool, typ int, n int64, isRetry bool) error {
	var (
		id  int64
		str string
		err error
	)

	if fifty {
		id, str, err = encid.Encode50(ctx, c.ks, typ, n)
	} else {
		id, str, err = encid.Encode(ctx, c.ks, typ, n)
	}
	if errors.Is(err, sql.ErrNoRows) && !isRetry {
		if _, err = c.newKeyHelper(ctx, typ); err != nil {
			return errors.Wrap(err, "creating new key")
		}
		return c.tryEnc(ctx, fifty, typ, n, true)
	}
	if err != nil {
		return errors.Wrap(err, "encoding")
	}

	fmt.Printf("%d %s\n", id, str)

	return nil
}

func (c maincmd) doDec(ctx context.Context, fifty bool, id int64, inp string, _ []string) error {
	var (
		typ int
		n   int64
		err error
	)

	if fifty {
		typ, n, err = encid.Decode50(ctx, c.ks, id, inp)
	} else {
		typ, n, err = encid.Decode(ctx, c.ks, id, inp)
	}
	if err != nil {
		return errors.Wrap(err, "decoding")
	}

	fmt.Printf("%d %d\n", typ, n)

	return nil
}

func (c maincmd) doNewKey(ctx context.Context, typ int, _ []string) error {
	id, err := c.newKeyHelper(ctx, typ)
	if err != nil {
		return err
	}

	fmt.Printf("%d\n", id)

	return nil
}

func (c maincmd) newKeyHelper(ctx context.Context, typ int) (int64, error) {
	return c.ks.NewKey(ctx, typ, aes.BlockSize)
}
