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

package kclient

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// CrdWatcher watches CustomResourceDefinition objects and lets callers block on,
// or register callbacks for, the appearance of a specific CRD.
type CrdWatcher = kube.CrdWatcher

// crdGVR is the CustomResourceDefinition resource the watcher lists and watches.
var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}

// CrdWatcherOptions configures the CRD filters applied by NewCrdWatcher.
type CrdWatcherOptions = kube.CrdWatcherOptions

type crdWatcher struct {
	crds    Informer[*metav1.PartialObjectMetadata]
	factory metadatainformer.SharedInformerFactory
	queue   controllers.Queue
	mutex   sync.RWMutex
	// filter decides whether a CRD is considered by the watcher. It is applied
	// both before enqueue and on read (see package comment).
	filter filterFunction

	callbacks map[string][]func()

	running chan struct{}
	stop    <-chan struct{}
}

// NewCrdWatcher returns a new CRD watcher controller backed by the given
// metadata client. The watcher builds and owns a metadata informer factory for
// the CustomResourceDefinition resource; Run starts it.
func NewCrdWatcher(md metadata.Interface, opts CrdWatcherOptions) CrdWatcher {
	return newCrdWatcher(md, opts)
}

func init() {
	kube.NewCrdWatcher = func(md metadata.Interface, options kube.CrdWatcherOptions) kube.CrdWatcher {
		return NewCrdWatcher(md, options)
	}
}

func newCrdWatcher(md metadata.Interface, opts CrdWatcherOptions) *crdWatcher {
	c := &crdWatcher{
		running:   make(chan struct{}),
		callbacks: map[string][]func(){},
	}

	filters := []filterFunction{minimumVersionFilter, maximumVersionFilter}

	if len(opts.IgnoreResources) > 0 {
		filters = append(filters,
			filterPilotResources(fetchResourceFilter(opts.IgnoreResources), fetchResourceFilter(opts.IncludeResources)),
		)
	}
	c.filter = unionFilter(filters)

	c.queue = controllers.NewQueue("crd watcher",
		controllers.WithReconciler(c.Reconcile))

	c.factory = metadatainformer.NewSharedInformerFactory(md, 0)
	informer := c.factory.ForResource(crdGVR).Informer()
	c.crds = New[*metav1.PartialObjectMetadata](informer)
	// CRDs failing the filter are never enqueued.
	c.crds.AddEventHandler(controllers.ObjectHandler(func(o controllers.Object) {
		if c.filter(o) {
			c.queue.AddObject(o)
		}
	}))
	return c
}

var minimumCRDVersions = map[string]*semver.Version{
	"grpcroutes.gateway.networking.k8s.io":         semver.New(1, 1, 0, "", ""),
	"backendtlspolicies.gateway.networking.k8s.io": semver.New(1, 4, 0, "", ""),
}

// MaximumCRDVersions specifies an inclusive upper bound on bundle versions for CRDs.
// A CRD whose bundle-version annotation is > the specified maximum will be filtered out.
// This is used when a Go client type targets an older API version that is no longer served
// by newer CRD bundles, preventing watch errors on startup.
var MaximumCRDVersions = map[string]*semver.Version{
	"tlsroutes.gateway.networking.k8s.io": semver.New(1, 4, 1, "", ""),
}

// resourceFilterConfig contains a filter definition parsed from the flags. In case
// the filter is passed with "*." the filter will be marked as Prefix type and
// the check will match the value as a suffix, and not as an exact match
type resourceFilterConfig struct {
	prefix bool
	value  string
}

// fetchResourceFilter is used to fetch the filters (ignore or include) from the
// flags.
func fetchResourceFilter(filters string) []resourceFilterConfig {
	resourceFilter := make([]resourceFilterConfig, 0)

	for filter := range strings.SplitSeq(filters, ",") {
		val := strings.TrimSpace(filter)
		prefix := false
		if strings.HasPrefix(val, "*.") {
			prefix = true
			val = strings.TrimPrefix(val, "*.")
		}
		filterConf := resourceFilterConfig{
			value:  val,
			prefix: prefix,
		}
		resourceFilter = append(resourceFilter, filterConf)
	}
	return resourceFilter
}

type filterFunction = func(obj any) bool

// unionFilter can be used to establish multiple object filters on CRD types.
// We can use it for cases where we care about filtering out a CRD for a specific
// version, or a specific group.
func unionFilter(fns []filterFunction) filterFunction {
	return func(obj any) bool {
		// if any of the functions returns false, early return the union
		for _, f := range fns {
			if !f(obj) {
				return false
			}
		}
		return true
	}
}

// filterPilotResources can be used in case we want to start the controller
// ignoring any Pilot resource.
// Two lists of resources will be passed. The passed resources can be prefixed with
// "*." meaning the match should be against the whole suffix and not the exact resource:
// - One list contains an array of resources that should be ignored/excluded.
// - One list contains an array of resources that should be always included, regardless
// of the exclusion list.
func filterPilotResources(pilotIgnoreResources, pilotIncludeResources []resourceFilterConfig) filterFunction {
	return func(t any) bool {
		crd := t.(*metav1.PartialObjectMetadata)

		// In case this resource is not on exclusion list, just return true value
		if !resourceMatchFilters(crd.Name, pilotIgnoreResources) {
			log.Info("CRD is not on ignore list; adding to watcher", "crd", crd.Name)
			return true
		}

		// Before excluding this resource, check if it belongs to inclusion list
		if resourceMatchFilters(crd.Name, pilotIncludeResources) {
			log.Info("CRD is explicitly included; adding to watcher", "crd", crd.Name)
			return true
		}
		log.Info("CRD is excluded from watcher", "crd", crd.Name)
		return false
	}
}

func resourceMatchFilters(name string, filters []resourceFilterConfig) bool {
	for _, filter := range filters {
		if (filter.prefix && strings.HasSuffix(name, filter.value)) ||
			(!filter.prefix && name == filter.value) {
			return true
		}
	}
	return false
}

// minimumVersionFilter filters CRDs that do not meet a minimum "version".
// Currently, we use this only for Gateway API CRD's, so we hardcode their versioning scheme.
// The problem we are trying to solve is:
// * User installs CRDs with Foo v1alpha1
// * The control plane starts watching Foo at a newer version
// * user upgrades. It sees Foo exists, and tries to watch the newer version. This fails.
func minimumVersionFilter(t any) bool {
	// Setup a filter
	crd := t.(*metav1.PartialObjectMetadata)
	mv, f := minimumCRDVersions[crd.Name]
	if !f {
		return true
	}
	bv, f := crd.Annotations[consts.BundleVersionAnnotation]
	if !f {
		log.Error("CRD is missing the expected annotation; ignoring",
			"crd", crd.Name, "annotation", consts.BundleVersion)
		return false
	}
	fv, err := semver.NewVersion(bv)
	if err != nil {
		log.Error("CRD version is invalid; ignoring", "crd", crd.Name, "version", bv, "error", err)
		return false
	}
	// Ignore RC tags, etc. We 'round up' those.
	nv, err := fv.SetPrerelease("")
	if err != nil {
		log.Error("CRD version is invalid; ignoring", "crd", crd.Name, "version", bv, "error", err)
		return false
	}
	fv = &nv
	if fv.LessThan(mv) {
		log.Info("CRD version is below minimum; ignoring", "crd", crd.Name,
			"version", fv, "minimum_version", mv)
		return false
	}
	return true
}

// maximumVersionFilter filters CRDs whose bundle-version annotation is above a specified maximum version.
// This is the complement of minimumVersionFilter: it rejects CRDs whose bundle version > the maximum,
// which is useful when a Go client type targets an older API version no longer served by newer CRD bundles.
func maximumVersionFilter(t any) bool {
	crd := t.(*metav1.PartialObjectMetadata)
	mv, f := MaximumCRDVersions[crd.Name]
	if !f {
		return true
	}
	bv, f := crd.Annotations[consts.BundleVersionAnnotation]
	if !f {
		log.Debug("CRD is missing the expected annotation; ignoring",
			"crd", crd.Name, "annotation", consts.BundleVersion)
		return false
	}
	fv, err := semver.NewVersion(bv)
	if err != nil {
		log.Debug("CRD version is invalid; ignoring", "crd", crd.Name, "version", bv, "error", err)
		return false
	}
	// Ignore RC tags, etc. We 'round up' those.
	nv, err := fv.SetPrerelease("")
	if err != nil {
		log.Debug("CRD version is invalid; ignoring", "crd", crd.Name, "version", bv, "error", err)
		return false
	}
	fv = &nv
	if fv.GreaterThan(mv) {
		log.Warn("CRD version is above maximum; ignoring", "crd", crd.Name,
			"version", fv, "maximum_version", mv)
		return false
	}
	return true
}

// HasSynced returns whether the underlying cache has synced and the callback has been called at least once.
func (c *crdWatcher) HasSynced() bool {
	return c.queue.HasSynced()
}

func (c *crdWatcher) Synced() <-chan struct{} { return c.queue.Synced() }

// Run starts the controller. This must be called.
func (c *crdWatcher) Run(stop <-chan struct{}) {
	c.mutex.Lock()
	if c.stop != nil {
		// Run already called. Because we call this from client.RunAndWait this isn't uncommon
		c.mutex.Unlock()
		return
	}
	c.stop = stop
	c.mutex.Unlock()
	// The watcher owns and starts its metadata informer factory.
	c.factory.Start(stop)
	kube.WaitForCacheSync("crd watcher", stop, c.crds.HasSynced)
	c.queue.Run(stop)
	log.Info("stopping CRD watcher")
	c.crds.ShutdownHandlers()
}

// WaitForCRD waits until the request CRD exists, and returns true on success. A false return value
// indicates the CRD does not exist but the wait failed or was canceled.
// This is useful to conditionally enable controllers based on CRDs being created.
func (c *crdWatcher) WaitForCRD(s schema.GroupVersionResource, stop <-chan struct{}) bool {
	done := make(chan struct{})
	if c.KnownOrCallback(s, func(stop <-chan struct{}) {
		close(done)
	}) {
		// Already known
		return true
	}
	select {
	case <-stop:
		return false
	case <-done:
		return true
	}
}

// KnownOrCallback returns `true` immediately if the resource is known.
// If it is not known, `false` is returned. If the resource is later added, the callback will be triggered.
func (c *crdWatcher) KnownOrCallback(s schema.GroupVersionResource, f func(stop <-chan struct{})) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// If we are already synced, return immediately if the CRD is present.
	if c.crds.HasSynced() && c.known(s) {
		// Already known, return early
		return true
	}
	name := fmt.Sprintf("%s.%s", s.Resource, s.Group)
	c.callbacks[name] = append(c.callbacks[name], func() {
		// Call the callback
		f(c.stop)
	})
	return false
}

func (c *crdWatcher) known(s schema.GroupVersionResource) bool {
	// From the spec: "Its name MUST be in the format <.spec.name>.<.spec.group>."
	name := fmt.Sprintf("%s.%s", s.Resource, s.Group)
	obj := c.crds.Get(name, "")
	if obj == nil {
		return false
	}
	// Re-apply the filter on read: the informer holds every CRD.
	return c.filter(obj)
}

func (c *crdWatcher) Reconcile(key types.NamespacedName) error {
	c.mutex.Lock()
	callbacks, f := c.callbacks[key.Name]
	if !f {
		c.mutex.Unlock()
		return nil
	}
	// Delete them so we do not run again
	delete(c.callbacks, key.Name)
	c.mutex.Unlock()
	for _, cb := range callbacks {
		cb()
	}
	return nil
}
