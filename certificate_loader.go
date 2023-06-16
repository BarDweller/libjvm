/*
 * Copyright 2018-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package libjvm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/effect"
	"github.com/paketo-buildpacks/libpak/sherpa"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"golang.org/x/sys/unix"
)

const DefaultCertFile = "/etc/ssl/certs/ca-certificates.crt"

var NormalizedDateTime = time.Date(1980, time.January, 1, 0, 0, 1, 0, time.UTC)

type CertificateLoader struct {
	CertFile       string
	CertDirs       []string
	Logger         bard.Logger
	Command        string
	PKCS12Keystore bool
}

func NewCertificateLoader() CertificateLoader {
	c := CertificateLoader{
		CertFile:       DefaultCertFile,
		PKCS12Keystore: false,
	}

	if s, ok := os.LookupEnv("SSL_CERT_FILE"); ok {
		c.CertFile = s
	}

	if s, ok := os.LookupEnv("SSL_CERT_DIR"); ok {
		c.CertDirs = filepath.SplitList(s)
	}

	return c
}

func (c *CertificateLoader) Load(path string, password string) error {
	ks, err := c.readKeyStore(path, password)
	if err != nil {
		return fmt.Errorf("unable to read keystore\n%w", err)
	}

	files, err := c.certFiles()
	if err != nil {
		return fmt.Errorf("unable to identify cert files in %s and %s\n%w", c.CertFile, c.CertDirs, err)
	}

	added := 0
	for _, f := range files {
		blocks, err := c.readBlocks(f)
		if err != nil {
			return fmt.Errorf("unable to read certificates from %s\n%w", f, err)
		}

		for i, b := range blocks {
			entry := keystore.TrustedCertificateEntry{
				CreationTime: NormalizedDateTime,
				Certificate: keystore.Certificate{
					Type:    "X.509",
					Content: b.Bytes,
				},
			}

			if err := ks.SetTrustedCertificateEntry(fmt.Sprintf("%s-%d", f, i), entry); err != nil {
				return fmt.Errorf("unable to add trusted entry\n%w", err)
			}

			added++
		}
	}

	c.Logger.Infof("Adding %d container CA certificates to JVM truststore\n", added)

	if c.PKCS12Keystore {
		return c.writePKCS12KeyStore(ks, path, password)
	}

	return c.writeKeyStore(ks, path, password)
}

func (c CertificateLoader) certFiles() ([]string, error) {
	var files []string

	if _, err := os.Stat(c.CertFile); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to stat %s\n%w", c.CertFile, err)
	} else if err == nil {
		files = append(files, c.CertFile)
	}

	re := regexp.MustCompile(`^[[:xdigit:]]{8}\.[\d]+$`)
	for _, d := range c.CertDirs {
		certs, err := os.ReadDir(d)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("unable to list children of %s\n%w", d, err)
		}

		for _, cert := range certs {
			if cert.IsDir() || !re.MatchString(cert.Name()) {
				continue
			}

			files = append(files, filepath.Join(d, cert.Name()))
		}
	}

	return files, nil
}

func (c *CertificateLoader) Metadata() (map[string]interface{}, error) {
	var (
		err      error
		metadata = make(map[string]interface{})
	)

	if in, err := os.Open(c.CertFile); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to open %s\n%w", c.CertFile, err)
	} else if err == nil {
		defer in.Close()

		out := sha256.New()
		if _, err := io.Copy(out, in); err != nil {
			return nil, fmt.Errorf("unable to hash file %s\n%w", c.CertFile, err)
		}
		metadata["cert-file"] = hex.EncodeToString(out.Sum(nil))
	}

	if metadata["cert-dir"], err = sherpa.NewFileListing(c.CertDirs...); err != nil {
		return nil, fmt.Errorf("unable to create file listing for %s\n%w", c.CertDirs, err)
	}

	return metadata, nil
}

func (c CertificateLoader) readBlocks(path string) ([]*pem.Block, error) {
	var (
		block  *pem.Block
		blocks []*pem.Block
	)

	rest, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s\n%w", path, err)
	}

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

func (c CertificateLoader) readKeyStore(path string, password string) (keystore.KeyStore, error) {
	if c.PKCS12Keystore {
		return keystore.New(keystore.WithOrderedAliases()), nil
	}
	in, err := os.Open(path)
	if err != nil {
		return keystore.KeyStore{}, fmt.Errorf("unable to open %s\n%w", path, err)
	}
	defer in.Close()

	ks := keystore.New(keystore.WithOrderedAliases())
	if err := ks.Load(in, []byte(password)); err != nil {
		return keystore.KeyStore{}, fmt.Errorf("unable to decode keystore\n %w", err)
	}

	return ks, nil
}

func (c CertificateLoader) writeKeyStore(ks keystore.KeyStore, path string, password string) error {
	if unix.Access(path, unix.W_OK) != nil {
		c.Logger.Bodyf("WARNING: Unable to add container CA certificates to JVM because %s is read-only", path)
		return nil
	}

	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to open %s\n%w", path, err)
	}
	defer out.Close()

	if err := ks.Store(out, []byte(password)); err != nil {
		return fmt.Errorf("unable to encode keystore\n%w", err)
	}

	return nil
}

func (c CertificateLoader) writePKCS12KeyStore(ks keystore.KeyStore, path string, password string) error {
	trustStore := filepath.Join("/tmp", "truststore")

	out, err := os.OpenFile(trustStore, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to open %s\n%w", trustStore, err)
	}
	defer out.Close()

	if err := ks.Store(out, []byte(password)); err != nil {
		return fmt.Errorf("unable to encode keystore\n%w", err)
	}

	args := []string{
		"-importkeystore",
		"-srckeystore",
		trustStore,
		"-srcstorepass",
		password,
		"-destkeystore",
		path,
		"-destprotected",
		"-noprompt",
	}

	if err := effect.NewExecutor().Execute(effect.Execution{
		Command: c.Command,
		Args:    args,
		Stdout:  &bytes.Buffer{},
		Stderr:  c.Logger.Logger.InfoWriter(),
	}); err != nil {
		return fmt.Errorf("unable to run keytool\n%w", err)
	}

	return nil
}
