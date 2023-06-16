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

package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paketo-buildpacks/libjvm"
	"github.com/paketo-buildpacks/libpak/bard"
	"golang.org/x/sys/unix"
)

type OpenSSLCertificateLoader18 struct {
	CertificateLoader libjvm.CertificateLoader
	Logger            bard.Logger
}

func (o OpenSSLCertificateLoader18) Execute() (map[string]string, error) {
	trustStore, ok := os.LookupEnv("BPI_JVM_CACERTS")
	if !ok {
		return nil, fmt.Errorf("$BPI_JVM_CACERTS must be set")
	}

	trustStoreWriteable := true
	if unix.Access(trustStore, unix.W_OK) != nil {
		trustStoreWriteable = false
	}

	var opts map[string]string
	if !trustStoreWriteable {
		o.Logger.Infof("Using readonly truststore: %s", TmpTrustStore)
		tmpOpts, err := prepareTempTrustStore(trustStore, TmpTrustStore)
		if err == nil {
			trustStore = TmpTrustStore
			opts = tmpOpts
		}
		o.Logger.Debugf("changed JAVA_TOOL_OPTIONS: '%s'", opts)
	}

	o.CertificateLoader.Logger = o.Logger
	o.CertificateLoader.PKCS12Keystore = true
	o.CertificateLoader.Command = filepath.Join(os.Getenv("JAVA_HOME"), "bin", "keytool")

	start := time.Now()
	if err := o.CertificateLoader.Load(trustStore, "changeit"); err != nil {
		return nil, fmt.Errorf("unable to load certificates\n%w", err)
	}
	o.Logger.Bodyf("Importing certificates took %dms", time.Since(start).Milliseconds())

	return opts, nil

}
