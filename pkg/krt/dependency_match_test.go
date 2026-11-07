// Copyright 2026 The Kruise Authors
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

package krt

import (
	"fmt"
	"testing"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

type dependencyMatchObject struct {
	Name, Namespace string
	Labels          map[string]string
}

func (o dependencyMatchObject) ResourceName() string         { return o.Namespace + "/" + o.Name }
func (o dependencyMatchObject) GetLabels() map[string]string { return o.Labels }

type dependencyCaptureContext struct {
	TestingDummyContext
	dependencies []*dependency
}

func (c *dependencyCaptureContext) registerDependency(
	d *dependency,
	_ Syncer,
	_ func(erasedEventHandler) HandlerRegistration,
) {
	c.dependencies = append(c.dependencies, d)
}

type dependencyMatchFixture struct {
	source      Collection[dependencyMatchObject]
	sourceID    collectionUID
	byNamespace Index[string, dependencyMatchObject]
	byName      Index[string, dependencyMatchObject]
	state       dependencyState[string]
}

func newDependencyMatchFixture(t testing.TB) *dependencyMatchFixture {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	source := NewStaticCollection[dependencyMatchObject](nil, nil, WithStop(stop))
	return &dependencyMatchFixture{
		source:   source,
		sourceID: source.uid(),
		byNamespace: NewIndex(source, "namespace", func(o dependencyMatchObject) []string {
			return []string{o.Namespace}
		}),
		byName: NewIndex(source, "name", func(o dependencyMatchObject) []string {
			return []string{o.Name}
		}),
		state: dependencyState[string]{
			indexedDependenciesExtractor: map[extractorKey]objectKeyExtractor{},
		},
	}
}

// Capture real Fetch registrations, then inspect invalidation synchronously.
// Output equality can otherwise hide a transform that needlessly ran.
func (f *dependencyMatchFixture) register(key string, queries ...[]FetchOption) {
	ctx := &dependencyCaptureContext{}
	for _, query := range queries {
		Fetch(ctx, f.source, query...)
	}
	f.state.update(Key[string](key), ctx.dependencies, 0)
}

func dependencyMatchValue(namespace, name, app string) *any {
	var value any = dependencyMatchObject{Name: name, Namespace: namespace, Labels: map[string]string{"app": app}}
	return &value
}

func TestDependencyMatchesCompleteQuery(t *testing.T) {
	t.Run("empty keys intersected with index", func(t *testing.T) {
		f := newDependencyMatchFixture(t)
		f.register("subject", []FetchOption{FilterIndex(f.byNamespace, "a"), FilterKeys([]string{}...)})
		if got := len(f.state.changedInputKeys(f.sourceID, []Event[any]{{New: dependencyMatchValue("a", "selected", "selected"), Event: controllers.EventAdd}})); got != 0 {
			t.Fatalf("empty query invalidated %d subjects, want 0", got)
		}
	})
	for _, mode := range []string{"namespace selectors", "index and explicit key", "index and empty keys", "different indexes"} {
		t.Run(mode, func(t *testing.T) {
			f := newDependencyMatchFixture(t)
			selected := []FetchOption{FilterIndex(f.byNamespace, "a"), FilterLabel(map[string]string{"app": "selected"})}
			queries := [][]FetchOption{selected}
			otherMatch := dependencyMatchValue("b", "other", "other")
			irrelevant := dependencyMatchValue("a", "other", "other")
			otherMatches := true
			switch mode {
			case "namespace selectors":
				queries = append(queries, []FetchOption{FilterIndex(f.byNamespace, "b"), FilterLabel(map[string]string{"app": "other"})})
			case "index and explicit key":
				queries[0] = []FetchOption{FilterIndex(f.byNamespace, "a"), FilterGeneric(func(o any) bool {
					return o.(dependencyMatchObject).Labels["app"] == "selected"
				})}
				queries = append(queries, []FetchOption{FilterKey("b/other")})
			case "index and empty keys":
				queries = append(queries, []FetchOption{FilterKeys([]string{}...)})
				otherMatches = false
			case "different indexes":
				queries = [][]FetchOption{{FilterIndex(f.byNamespace, "a")}, {FilterIndex(f.byName, "other")}}
				// The name index key collides with a namespace index key.
				irrelevant = dependencyMatchValue("c", "a", "other")
			}
			for i := range 32 {
				f.register(fmt.Sprintf("subject-%d", i), queries...)
			}
			match := dependencyMatchValue("a", "selected", "selected")
			for _, tc := range []struct {
				name  string
				event Event[any]
				want  int
			}{
				{"unrelated add", Event[any]{New: irrelevant, Event: controllers.EventAdd}, 0},
				{"unrelated update", Event[any]{Old: irrelevant, New: irrelevant, Event: controllers.EventUpdate}, 0},
				{"unrelated delete", Event[any]{Old: irrelevant, Event: controllers.EventDelete}, 0},
				{"matching add", Event[any]{New: match, Event: controllers.EventAdd}, 32},
				{"starts matching", Event[any]{Old: irrelevant, New: match, Event: controllers.EventUpdate}, 32},
				{"stops matching", Event[any]{Old: match, New: irrelevant, Event: controllers.EventUpdate}, 32},
				{"matching delete", Event[any]{Old: match, Event: controllers.EventDelete}, 32},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if got := len(f.state.changedInputKeys(f.sourceID, []Event[any]{tc.event})); got != tc.want {
						t.Fatalf("invalidated %d subjects, want %d", got, tc.want)
					}
				})
			}
			if mode == "namespace selectors" {
				// Neither side of this update matches a complete query. An index
				// hit on the old object must not prefilter the new object, or vice versa.
				event := Event[any]{Old: irrelevant, New: dependencyMatchValue("b", "other", "selected"), Event: controllers.EventUpdate}
				if got := len(f.state.changedInputKeys(f.sourceID, []Event[any]{event})); got != 0 {
					t.Fatalf("crossed old/new conditions invalidated %d subjects, want 0", got)
				}
			}
			want := 0
			if otherMatches {
				want = 32
			}
			if got := len(f.state.changedInputKeys(f.sourceID, []Event[any]{{New: otherMatch, Event: controllers.EventAdd}})); got != want {
				t.Fatalf("other dependency invalidated %d subjects, want %d", got, want)
			}
			// Re-registering an input must replace its old dependencies.
			f.register("subject-0", []FetchOption{FilterKey("elsewhere/replacement")})
			if got := len(f.state.changedInputKeys(f.sourceID, []Event[any]{{New: match, Event: controllers.EventAdd}})); got != 31 {
				t.Fatalf("old dependency invalidated %d subjects after replacement, want 31", got)
			}
			if got := len(f.state.changedInputKeys(f.sourceID, []Event[any]{{New: dependencyMatchValue("elsewhere", "replacement", ""), Event: controllers.EventAdd}})); got != 1 {
				t.Fatalf("replacement dependency invalidated %d subjects, want 1", got)
			}
		})
	}
}

func BenchmarkDependencyMatching(b *testing.B) {
	for _, mode := range []string{"exact-key", "namespace", "namespace-selector", "mixed-namespace-selectors"} {
		b.Run(mode, func(b *testing.B) {
			f := newDependencyMatchFixture(b)
			for i := range 1000 {
				name := fmt.Sprintf("subject-%d", i)
				switch mode {
				case "exact-key":
					f.register(name, []FetchOption{FilterKey("a/" + name)})
				case "namespace":
					f.register(name, []FetchOption{FilterIndex(f.byNamespace, "a")})
				default:
					queries := [][]FetchOption{{FilterIndex(f.byNamespace, "a"), FilterLabel(map[string]string{"app": name})}}
					if mode == "mixed-namespace-selectors" {
						queries = append(queries, []FetchOption{FilterIndex(f.byNamespace, "b"), FilterLabel(map[string]string{"app": "subject-0"})})
					}
					f.register(name, queries...)
				}
			}
			events := []Event[any]{{New: dependencyMatchValue("a", "subject-0", "subject-0"), Event: controllers.EventAdd}}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				f.state.changedInputKeys(f.sourceID, events)
			}
		})
	}
}
