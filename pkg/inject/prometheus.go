// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inject

import (
	"encoding/json"
	"regexp"
	"strconv"

	corev1 "k8s.io/api/core/v1"

	"istio.io/istio/pkg/util/sets"
)

const (
	// prometheus will convert annotation to this format
	// `prometheus.io/scrape` `prometheus.io.scrape` `prometheus-io/scrape` have the same meaning in Prometheus
	prometheusScrapeAnnotation = "prometheus_io_scrape"
	prometheusPortAnnotation   = "prometheus_io_port"
	prometheusPathAnnotation   = "prometheus_io_path"
)

func enablePrometheusMerge(configured bool, anno map[string]string) bool {
	// If annotation is present, we look there first
	if val, f := anno[prometheusMergeAnnotation]; f {
		bval, err := strconv.ParseBool(val)
		if err != nil {
			// This shouldn't happen since we validate earlier in the code
			log.Warn("invalid annotation", "annotation", prometheusMergeAnnotation, "value", bval)
		} else {
			return bval
		}
	}
	return configured
}

var emptyScrape = PrometheusScrapeConfiguration{}

// applyPrometheusMerge configures prometheus scraping annotations for the "metrics merge" feature.
// This moves the current prometheus.io annotations into an environment variable and replaces them
// pointing to the agent.
func applyPrometheusMerge(pod *corev1.Pod, settings InjectionSettings) error {
	if getPrometheusScrape(pod) &&
		enablePrometheusMerge(settings.EnablePrometheusMerge, pod.ObjectMeta.Annotations) {
		targetPort := strconv.Itoa(settings.StatusPort)
		if cur, f := getPrometheusPort(pod); f {
			// We have already set the port, assume user is controlling this or, more likely, re-injected
			// the pod.
			if cur == targetPort {
				return nil
			}
		}
		scrape := getPrometheusScrapeConfiguration(pod)
		sidecar := FindSidecar(pod)
		if sidecar != nil && scrape != emptyScrape {
			by, err := json.Marshal(scrape)
			if err != nil {
				return err
			}
			sidecar.Env = append(sidecar.Env, corev1.EnvVar{Name: PrometheusScrapingConfigName, Value: string(by)})
		}
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		// if a user sets `prometheus/io/path: foo`, then we add `prometheus.io/path: /stats/prometheus`
		// prometheus will pick a random one
		// need to clear out all variants and then set ours
		clearPrometheusAnnotations(pod)
		pod.Annotations["prometheus.io/port"] = targetPort
		pod.Annotations["prometheus.io/path"] = "/stats/prometheus"
		pod.Annotations["prometheus.io/scrape"] = "true"
		return nil
	}

	return nil
}

// invalidPrometheusLabelChars mirrors Prometheus strutil.SanitizeLabelName,
// which replaces every character outside [a-zA-Z0-9_] with an underscore.
var invalidPrometheusLabelChars = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func sanitizeLabelName(name string) string {
	return invalidPrometheusLabelChars.ReplaceAllString(name, "_")
}

// getPrometheusScrape respect prometheus scrape config
// not to doing prometheusMerge if this return false
func getPrometheusScrape(pod *corev1.Pod) bool {
	for k, val := range pod.Annotations {
		if sanitizeLabelName(k) != prometheusScrapeAnnotation {
			continue
		}

		if scrape, err := strconv.ParseBool(val); err == nil {
			return scrape
		}
	}

	return true
}

var prometheusAnnotations = sets.New(
	prometheusPathAnnotation,
	prometheusPortAnnotation,
	prometheusScrapeAnnotation,
)

func clearPrometheusAnnotations(pod *corev1.Pod) {
	needRemovedKeys := make([]string, 0, 2)
	for k := range pod.Annotations {
		anno := sanitizeLabelName(k)
		if prometheusAnnotations.Contains(anno) {
			needRemovedKeys = append(needRemovedKeys, k)
		}
	}

	for _, k := range needRemovedKeys {
		delete(pod.Annotations, k)
	}
}

func getPrometheusScrapeConfiguration(pod *corev1.Pod) PrometheusScrapeConfiguration {
	cfg := PrometheusScrapeConfiguration{}

	for k, val := range pod.Annotations {
		anno := sanitizeLabelName(k)
		switch anno {
		case prometheusPortAnnotation:
			cfg.Port = val
		case prometheusScrapeAnnotation:
			cfg.Scrape = val
		case prometheusPathAnnotation:
			cfg.Path = val
		}
	}

	return cfg
}

func getPrometheusPort(pod *corev1.Pod) (string, bool) {
	for k, val := range pod.Annotations {
		if sanitizeLabelName(k) != prometheusPortAnnotation {
			continue
		}

		return val, true
	}

	return "", false
}
