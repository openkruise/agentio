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

package check

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/components/echo"
)

func TestCheckersAcceptExpectedOutcomes(t *testing.T) {
	success := echo.Result{Responses: []echo.Response{
		{StatusCode: 200, Hostname: "server-a"},
		{StatusCode: 200, Hostname: "server-a"},
	}}
	callErr := fakeCommandExitError{code: 1, err: errors.New("connection refused")}
	tests := []struct {
		name    string
		checker echo.Checker
		result  echo.Result
		err     error
	}{
		{name: "and OK", checker: And(OK(), ReachedWorkloads(1)), result: success},
		{name: "no error", checker: NoError(), result: success},
		{name: "status", checker: Status(200), result: success},
		{name: "expected error", checker: Error(), err: callErr},
		{name: "expected error text", checker: ErrorContains("refused"), err: callErr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.checker(tc.result, tc.err); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestErrorRejectsInfrastructureFailure(t *testing.T) {
	err := Error()(echo.Result{}, errors.New("unable to upgrade SPDY connection"))
	if err == nil || !strings.Contains(err.Error(), "request command") {
		t.Fatalf("Error() = %v, want an unclassified infrastructure failure", err)
	}
}

type fakeCommandExitError struct {
	code int
	err  error
}

func (e fakeCommandExitError) Error() string   { return fmt.Sprintf("exit %d: %v", e.code, e.err) }
func (e fakeCommandExitError) Unwrap() error   { return e.err }
func (e fakeCommandExitError) Exited() bool    { return true }
func (e fakeCommandExitError) ExitStatus() int { return e.code }

func TestCheckersExplainMismatches(t *testing.T) {
	result := echo.Result{Responses: []echo.Response{{StatusCode: 503, Hostname: "server-a"}}}
	tests := []struct {
		name    string
		checker echo.Checker
		err     error
		want    string
	}{
		{name: "no error", checker: NoError(), err: errors.New("connection refused"), want: "connection refused"},
		{name: "error", checker: Error(), want: "expected an error"},
		{name: "error text", checker: ErrorContains("reset"), err: errors.New("connection refused"), want: "reset"},
		{name: "status", checker: Status(200), want: "503"},
		{name: "workloads", checker: ReachedWorkloads(2), want: "1 workload"},
		{name: "and", checker: And(NoError(), Status(200)), want: "503"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.checker(result, tc.err)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEachReportsResponseIndex(t *testing.T) {
	result := echo.Result{Responses: []echo.Response{{StatusCode: 200}, {StatusCode: 503}}}
	err := Each(func(response echo.Response) error {
		if response.StatusCode != 200 {
			return errors.New("unexpected status")
		}
		return nil
	})(result, nil)
	if err == nil || !strings.Contains(err.Error(), "response 1") || !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("error = %v, want response index and visitor error", err)
	}
}

func TestHeaderCheckersMatchCaseInsensitiveValuesAcrossResponses(t *testing.T) {
	responses, err := echo.ParseResponses(`[0] RequestHeader=X-Request-ID:request-a
[0] ResponseHeader=X-Response-ID:response-a
[1] RequestHeader=x-request-id:request-a
[1] ResponseHeader=x-response-id:response-a`)
	if err != nil {
		t.Fatal(err)
	}
	result := echo.Result{Responses: responses}
	for _, checker := range []echo.Checker{
		RequestHeader("x-request-id", "request-a"),
		ResponseHeader("X-RESPONSE-ID", "response-a"),
	} {
		if err := checker(result, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBodyContainsSearchesRawContentAndBodyValues(t *testing.T) {
	responses, err := echo.ParseResponses(`[0] arbitrary raw marker
[1] arbitrary raw marker`)
	if err != nil {
		t.Fatal(err)
	}
	for index := range responses {
		responses[index].Body["detail"] = "body marker"
	}
	result := echo.Result{Responses: responses}
	for _, want := range []string{"raw marker", "body marker"} {
		if err := BodyContains(want)(result, nil); err != nil {
			t.Fatalf("BodyContains(%q): %v", want, err)
		}
	}
}

func TestNotStatusRejectsForbiddenStatusFromAnyResponse(t *testing.T) {
	result := echo.Result{Responses: []echo.Response{{StatusCode: 200}, {StatusCode: 503}}}
	if err := NotStatus(503)(result, nil); err == nil || !strings.Contains(err.Error(), "response 1") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %v, want forbidden response status", err)
	}
}
