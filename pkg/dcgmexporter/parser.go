/*
 * Copyright (c) 2021, NVIDIA CORPORATION.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dcgmexporter

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/NVIDIA/go-dcgm/pkg/dcgm"
	"github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	CPU_FIELDS_START = 1100
	DCP_FIELDS_START = 1000
)

func ExtractCounters(c *Config) ([]Counter, []Counter, error) {
	var err error
	var records [][]string

	if c.ConfigMapData != undefinedConfigMapData {
		var client kubernetes.Interface
		client, err = getKubeClient()
		if err != nil {
			logrus.Fatal(err)
		}
		records, err = readConfigMap(client, c)
		if err != nil {
			logrus.Fatal(err)
		}
	} else {
		logrus.Infof("No configmap data specified")
	}

	if err != nil || c.ConfigMapData == undefinedConfigMapData {
		logrus.Infof("Falling back to metric file '%s'", c.CollectorsFile)

		records, err = ReadCSVFile(c.CollectorsFile)
		if err != nil {
			logrus.Errorf("Could not read metrics file '%s'; err: %v", c.CollectorsFile, err)
			return nil, nil, err
		}
	}

	counters, extraCounters, err := extractCounters(records, c)
	if err != nil {
		return nil, nil, err
	}

	return counters, extraCounters, err
}

func ReadCSVFile(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	r := csv.NewReader(file)
	r.Comment = '#'
	records, err := r.ReadAll()

	return records, err
}

func extractCounters(records [][]string, c *Config) ([]Counter, []Counter, error) {
	f := make([]Counter, 0, len(records))
	expf := make([]Counter, 0)

	for i, record := range records {
		var useOld = false
		if len(record) == 0 {
			continue
		}

		for j, r := range record {
			record[j] = strings.Trim(r, " ")
		}

		if len(record) != 3 {
			return nil, nil, fmt.Errorf("malformed CSV record; err: failed to parse line %d (`%v`), "+
				"expected 3 fields", i,
				record)
		}

		fieldID, ok := dcgm.DCGM_FI[record[0]]
		oldFieldID, oldOk := dcgm.OLD_DCGM_FI[record[0]]
		if !ok && !oldOk {

			expField, err := IdentifyMetricType(record[0])
			if err != nil {
				return nil, nil, fmt.Errorf("could not find DCGM field; err: %w", err)
			} else if expField != DCGMFIUnknown {
				expf = append(expf, Counter{dcgm.Short(expField), record[0], record[1], record[2]})
				continue
			}
		}

		if !ok && oldOk {
			useOld = true
		}

		if !useOld {
			if !fieldIsSupported(uint(fieldID), c) {
				logrus.Warnf("Skipping line %d ('%s'): metric not enabled", i, record[0])
				continue
			}

			if _, ok := promMetricType[record[1]]; !ok {
				return nil, nil, fmt.Errorf("could not find Prometheus metric type '%s'", record[1])
			}

			f = append(f, Counter{fieldID, record[0], record[1], record[2]})
		} else {
			if !fieldIsSupported(uint(oldFieldID), c) {
				logrus.Warnf("Skipping line %d ('%s'): metric not enabled", i, record[0])
				continue
			}

			if _, ok := promMetricType[record[1]]; !ok {
				return nil, nil, fmt.Errorf("could not find Prometheus metric type '%s'", record[1])
			}

			f = append(f, Counter{oldFieldID, record[0], record[1], record[2]})

		}
	}

	return f, expf, nil
}

func fieldIsSupported(fieldID uint, c *Config) bool {
	if fieldID < DCP_FIELDS_START || fieldID >= CPU_FIELDS_START {
		return true
	}

	if !c.CollectDCP {
		return false
	}

	for i := int(0); i < len(c.MetricGroups); i++ {
		for j := int(0); j < len(c.MetricGroups[i].FieldIds); j++ {
			if fieldID == c.MetricGroups[i].FieldIds[j] {
				return true
			}
		}
	}

	return false
}

func readConfigMap(kubeClient kubernetes.Interface, c *Config) ([][]string, error) {
	parts := strings.Split(c.ConfigMapData, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed configmap-data '%s'", c.ConfigMapData)
	}

	var cm *corev1.ConfigMap
	cm, err := kubeClient.CoreV1().ConfigMaps(parts[0]).Get(context.TODO(), parts[1], metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not retrieve ConfigMap '%s'; err: %w", c.ConfigMapData, err)
	}

	if _, ok := cm.Data["metrics"]; !ok {
		return nil, fmt.Errorf("malformed ConfigMap '%s'; no 'metrics' key", c.ConfigMapData)
	}

	r := csv.NewReader(strings.NewReader(cm.Data["metrics"]))
	r.Comment = '#'
	records, err := r.ReadAll()

	if len(records) == 0 {
		return nil, fmt.Errorf("malformed configmap contents; err: no metrics found")
	}

	return records, err
}

func getKubeClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return client, err
}
