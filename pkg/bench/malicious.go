/*
 * Warp (C) 2019-2020 MinIO, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package bench

import (
	"context"
	"math/rand"
	"time"

	"github.com/minio/minio-go/v7"
)

// MaliciousOpType is the OpType recorded for malicious operations so they can
// be filtered separately during analysis.
const MaliciousOpType = "MALICIOUS"

// MaliciousCategory identifies the class of adversarial behaviour to simulate.
type MaliciousCategory string

const (
	// MaliciousMalformed sends requests with invalid bucket/object names,
	// bad HTTP methods, oversized headers, or malformed auth signatures.
	MaliciousMalformed MaliciousCategory = "malformed"

	// MaliciousAuth sends requests with expired credentials, wrong signatures,
	// missing auth headers, or fuzzed credential values.
	MaliciousAuth MaliciousCategory = "auth"

	// MaliciousAccessControl probes objects and buckets outside the test
	// prefix to check whether the server enforces authorization boundaries.
	MaliciousAccessControl MaliciousCategory = "access-control"

	// MaliciousResourceExhaust attempts to exhaust server resources via
	// extremely large uploads, tiny chunk sizes, or rapid-fire requests.
	MaliciousResourceExhaust MaliciousCategory = "resource-exhaustion"
)

// allMaliciousCategories is the ordered list used when picking a random category.
var allMaliciousCategories = []MaliciousCategory{
	MaliciousMalformed,
	MaliciousAuth,
	MaliciousAccessControl,
	MaliciousResourceExhaust,
}

// MaliciousConfig holds per-category configuration for the malicious traffic
// generator.  All categories are active by default when MaliciousPct > 0.
type MaliciousConfig struct {
	// EnabledCategories lists which categories are active.
	// When empty every category in allMaliciousCategories is used.
	EnabledCategories []MaliciousCategory
}

// activeCategories returns the effective set of categories to sample from.
func (c MaliciousConfig) activeCategories() []MaliciousCategory {
	if len(c.EnabledCategories) == 0 {
		return allMaliciousCategories
	}
	return c.EnabledCategories
}

// shouldMalicious returns true with probability pct/100, using rng for
// reproducibility within a benchmark thread.
func shouldMalicious(rng *rand.Rand, pct float64) bool {
	return rng.Float64()*100 < pct
}

// MaybeExecMalicious is called from within each benchmark's operation loop
// immediately after the RPS limiter check.  It returns nil when this
// iteration should proceed as a normal operation.  When the random draw
// fires it acquires a client connection, executes a malicious S3 request, and
// returns the recorded Operation so the caller can forward it to the
// Collector.
//
// Canonical call-site pattern (to be added inside each benchmark's Start()
// goroutine loop, after rpsLimit and before the normal S3 call):
//
//	if op := c.MaybeExecMalicious(ctx, rng, uint32(i)); op != nil {
//	    rcv <- *op
//	    continue
//	}
func (c *Common) MaybeExecMalicious(ctx context.Context, rng *rand.Rand, thread uint32) *Operation {
	if c.MaliciousPct <= 0 {
		return nil
	}
	if !shouldMalicious(rng, c.MaliciousPct) {
		return nil
	}

	client, cldone := c.Client()
	defer cldone()

	categories := c.MaliciousConfig.activeCategories()
	cat := categories[rng.Intn(len(categories))]

	var op Operation
	switch cat {
	case MaliciousMalformed:
		op = execMalformedRequest(ctx, client, c.Bucket, thread)
	case MaliciousAuth:
		op = execAuthAttack(ctx, client, c.Bucket, thread)
	case MaliciousAccessControl:
		op = execAccessControlProbe(ctx, client, c.Bucket, thread)
	case MaliciousResourceExhaust:
		op = execResourceExhaustion(ctx, client, c.Bucket, thread)
	}

	op.OpType = MaliciousOpType
	op.Thread = thread
	op.Endpoint = client.EndpointURL().String()
	return &op
}

// execMalformedRequest sends one or more requests with structurally invalid
// parameters (bad object names, unknown HTTP verbs, oversized headers, …) and
// returns the recorded Operation.
//
// TODO: implement.
func execMalformedRequest(_ context.Context, _ *minio.Client, _ string, _ uint32) Operation {
	start := time.Now()
	return Operation{
		Start: start,
		End:   time.Now(),
		Err:   "not implemented: malformed-request",
	}
}

// execAuthAttack sends a request crafted to probe authentication weaknesses
// (expired/invalid credentials, missing signature, fuzzed auth header) and
// returns the recorded Operation.
//
// TODO: implement.
func execAuthAttack(_ context.Context, _ *minio.Client, _ string, _ uint32) Operation {
	start := time.Now()
	return Operation{
		Start: start,
		End:   time.Now(),
		Err:   "not implemented: auth-attack",
	}
}

// execAccessControlProbe attempts to read or write objects outside the
// benchmark prefix/bucket to verify that authorization boundaries are
// enforced, and returns the recorded Operation.
//
// TODO: implement.
func execAccessControlProbe(_ context.Context, _ *minio.Client, _ string, _ uint32) Operation {
	start := time.Now()
	return Operation{
		Start: start,
		End:   time.Now(),
		Err:   "not implemented: access-control-probe",
	}
}

// execResourceExhaustion attempts to exhaust server-side resources (e.g. via
// an extremely large upload body or rapid sub-chunk requests) and returns the
// recorded Operation.
//
// TODO: implement.
func execResourceExhaustion(_ context.Context, _ *minio.Client, _ string, _ uint32) Operation {
	start := time.Now()
	return Operation{
		Start: start,
		End:   time.Now(),
		Err:   "not implemented: resource-exhaustion",
	}
}
