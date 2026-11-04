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

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/golang/protobuf/jsonpb"            //nolint:staticcheck // Preserve AgentioConfig field replacement semantics.
	legacyproto "github.com/golang/protobuf/proto" //nolint:staticcheck // jsonpb accepts the legacy message adapter.
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"sigs.k8s.io/yaml"
)

// Apply decodes YAML/JSON onto a copy of base, which must be non-nil. Omitted
// and null fields preserve base; supplied fields replace lists and submessages.
// Unknown fields are ignored with a warning. Invalid known fields, duplicate
// YAML keys, and conflicting oneof members are errors.
func Apply[T proto.Message](content string, base T) (T, error) {
	var zero T
	data, err := yaml.YAMLToJSONStrict([]byte(content))
	if err != nil {
		return zero, fmt.Errorf("parse YAML: %w", err)
	}
	value := proto.Clone(base).(T)
	if string(data) == "null" {
		return value, nil
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return zero, fmt.Errorf("decode configuration JSON: %w", err)
	}
	unknown := discardUnknownFields(document, base.ProtoReflect().Descriptor(), "")
	if len(unknown) > 0 {
		data, err = json.Marshal(document)
		if err != nil {
			return zero, fmt.Errorf("encode known configuration fields: %w", err)
		}
	}
	// jsonpb supplies presence-aware replacement, but accepts conflicting oneofs.
	// Keep protojson strict: DiscardUnknown also accepts invalid enum names.
	if err := protojson.Unmarshal(data, base.ProtoReflect().New().Interface()); err != nil {
		return zero, fmt.Errorf("decode configuration: %w", err)
	}
	if err := jsonpb.UnmarshalString(string(data), legacyproto.MessageV1(value)); err != nil {
		return zero, fmt.Errorf("apply configuration: %w", err)
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		log.Warn(
			"ignore unknown configuration fields",
			"type",
			base.ProtoReflect().Descriptor().FullName(),
			"fields",
			unknown,
		)
	}
	return value, nil
}

func discardUnknownFields(value any, message protoreflect.MessageDescriptor, path string) []string {
	// Well-known types have custom JSON encodings, including arbitrary Struct keys.
	if message == nil || message.ParentFile().Package() == "google.protobuf" {
		return nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	var unknown []string
	for name, value := range object {
		fieldPath := name
		if path != "" {
			fieldPath = path + "." + name
		}
		field := message.Fields().ByJSONName(name)
		if field == nil {
			field = message.Fields().ByName(protoreflect.Name(name))
		}
		if field == nil {
			delete(object, name)
			unknown = append(unknown, fieldPath)
			continue
		}
		switch {
		case field.IsMap():
			entries, _ := value.(map[string]any)
			for key, entry := range entries {
				unknown = append(
					unknown,
					discardUnknownFields(entry, field.MapValue().Message(), fmt.Sprintf("%s[%q]", fieldPath, key))...)
			}
		case field.IsList():
			entries, _ := value.([]any)
			for i, entry := range entries {
				unknown = append(
					unknown,
					discardUnknownFields(entry, field.Message(), fmt.Sprintf("%s[%d]", fieldPath, i))...)
			}
		default:
			unknown = append(unknown, discardUnknownFields(value, field.Message(), fieldPath)...)
		}
	}
	return unknown
}
