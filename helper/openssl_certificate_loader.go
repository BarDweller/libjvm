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
	"github.com/paketo-buildpacks/libjvm"
	"github.com/paketo-buildpacks/libpak/bard"
	"os"
)

type OpenSSLCertificateLoader struct {
	CertificateLoader libjvm.CertificateLoader
	Logger            bard.Logger
	KeystoreOps       libjvm.KeystoreOps
}

func (o OpenSSLCertificateLoader) Execute() (map[string]string, error) {
	k, ok := os.LookupEnv("BPI_JVM_CACERTS")
	if !ok {
		return nil, fmt.Errorf("$BPI_JVM_CACERTS must be set")
	}

	o.CertificateLoader.Logger = o.Logger.InfoWriter()

	systemCerts, err := o.CertificateLoader.LoadSystemCerts()
	if err != nil {
		return nil, fmt.Errorf("unable to load system certificates\n%w", err)
	}
	if err := libjvm.CombineCerts(k, systemCerts, o.CertificateLoader.Logger); err != nil {
		return nil, fmt.Errorf("unable to read JVM Keystore\n%w", err)
	}

	return nil, nil
}
