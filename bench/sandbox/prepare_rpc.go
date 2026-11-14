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

package main

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (r *runner) prepareRPC(ctx context.Context) (any, error) {
	c, err := grpc.NewClient(r.Target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer closeResource(c)
	ctx, cancel := context.WithTimeout(ctx, r.Duration)
	defer cancel()
	start := time.Now()
	// PrepareSandboxRequest.sandbox_id is protobuf string field 1, identical on the wire.
	err = c.Invoke(
		ctx,
		"/agentio.network.v1.SandboxNetwork/PrepareSandbox",
		wrapperspb.String(r.Prefix),
		&emptypb.Empty{},
	)
	return map[string]any{
		"code":    status.Code(err).String(),
		"seconds": time.Since(start).Seconds(),
		"message": status.Convert(err).Message(),
	}, err
}
