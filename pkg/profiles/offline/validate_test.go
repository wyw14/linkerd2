package offline

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustValidate(t *testing.T, docs string) *Report {
	t.Helper()
	report, err := ValidateBytes([]byte(docs))
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	return report
}

type diagKey struct {
	severity Severity
	path     string
	reason   string
}

func diagKeys(t *testing.T, report *Report) []diagKey {
	t.Helper()
	diags := report.Diagnostics()
	keys := make([]diagKey, 0, len(diags))
	for _, d := range diags {
		keys = append(keys, diagKey{severity: d.Severity, path: d.Path, reason: d.Reason})
	}
	return keys
}

func assertDiags(t *testing.T, report *Report, expected []diagKey) {
	t.Helper()
	got := diagKeys(t, report)
	if len(got) != len(expected) {
		t.Fatalf("expected %d diagnostics, got %d:\n%v", len(expected), len(got), got)
	}
	for i, want := range expected {
		if got[i] != want {
			t.Fatalf("diagnostic %d: expected %+v, got %+v", i, want, got[i])
		}
	}
}

func hasDiag(report *Report, path, reason string, severity Severity) bool {
	for _, d := range report.Diagnostics() {
		if d.Path == path && d.Reason == reason && d.Severity == severity {
			return true
		}
	}
	return false
}

const validServiceProfile = `apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  retryBudget:
    retryRatio: 0.2
    minRetriesPerSecond: 10
    ttl: 10s
  routes:
  - name: GET v1
    timeout: 5s
    condition:
      method: GET
      pathRegex: /v1/.*
    responseClasses:
    - condition:
        status:
          min: 500
          max: 599
      isFailure: true
  dstOverrides:
  - authority: web-backup.foo.svc.cluster.local:8080
    weight: "1"
`

func TestEmptyProfile(t *testing.T) {
	emptyProfiles := []string{
		`apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec: {}
`,
		`apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
`,
	}
	for i, doc := range emptyProfiles {
		report := mustValidate(t, doc)
		if report.HasErrors() {
			t.Fatalf("case %d: empty profile must validate without errors: %+v", i, report.Diagnostics())
		}
		if len(report.Diagnostics()) != 0 {
			t.Fatalf("case %d: empty profile must produce no diagnostics, got %+v", i, report.Diagnostics())
		}
	}
}

func TestValidFullProfile(t *testing.T) {
	report := mustValidate(t, validServiceProfile)
	assertDiags(t, report, nil)
}

func TestUnknownFieldsPreserved(t *testing.T) {
	docs := `apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
  annotations:
    future.example.com/unknown: kept
spec:
  futureField: preserve-me
  routes:
  - name: r1
    condition:
      method: GET
    futureRouteField: 42
`
	report := mustValidate(t, docs)
	if len(report.Diagnostics()) != 0 {
		t.Fatalf("unknown fields must not be rejected: %+v", report.Diagnostics())
	}

	rawDocs, err := report.Documents()
	if err != nil {
		t.Fatalf("failed to render documents: %v", err)
	}
	if len(rawDocs) != 1 {
		t.Fatalf("expected one retained document, got %d", len(rawDocs))
	}
	rendered := string(rawDocs[0])
	for _, want := range []string{"futureField", "preserve-me", "futureRouteField", "future.example.com/unknown"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("unknown field %q must be retained, document:\n%s", want, rendered)
		}
	}

	// The retained snapshot still exposes the typed object for consumers.
	if report.Snapshot().Objects[0].Profile == nil {
		t.Fatal("typed ServiceProfile must remain available")
	}
}

func TestServiceProfileDiagnostics(t *testing.T) {
	cases := []struct {
		name     string
		spec     string
		expected []diagKey
	}{
		{
			name: "invalid profile name",
			spec: `metadata:
  name: NOT_VALID
  namespace: foo
spec: {}
`,
			expected: []diagKey{
				{SeverityError, "metadata.name", ReasonInvalidName},
			},
		},
		{
			name: "namespace mismatch",
			spec: `metadata:
  name: web.bar.svc.cluster.local
  namespace: foo
spec: {}
`,
			expected: []diagKey{
				{SeverityWarning, "metadata.name", ReasonNamespaceMismatch},
			},
		},
		{
			name: "null route",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  -
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0]", ReasonNullEntry},
			},
		},
		{
			name: "missing and duplicate route names",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  - condition:
      method: GET
  - name: r1
    condition:
      method: GET
  - name: r1
    condition:
      method: GET
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0].name", ReasonRequired},
				{SeverityError, "spec.routes[2].name", ReasonDuplicateName},
			},
		},
		{
			name: "invalid and negative timeouts",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  - name: bad
    condition: {method: GET}
    timeout: one-second
  - name: neg
    condition: {method: GET}
    timeout: -1s
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0].timeout", ReasonInvalidDuration},
				{SeverityError, "spec.routes[1].timeout", ReasonNegativeDuration},
			},
		},
		{
			name: "missing condition and empty match",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  - name: none
  - name: empty
    condition: {}
  - name: nested
    condition:
      all:
      - {}
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0].condition", ReasonRequired},
				{SeverityError, "spec.routes[1].condition", ReasonInvalidMatch},
				{SeverityError, "spec.routes[2].condition.all[0]", ReasonInvalidMatch},
			},
		},
		{
			name: "null nested conditions",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  - name: r
    condition:
      any:
      -
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0].condition.any[0]", ReasonNullEntry},
			},
		},
		{
			name: "response class status ranges",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  - name: r
    condition: {method: GET}
    responseClasses:
    - condition:
        status: {min: 700, max: 500}
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0].responseClasses[0].condition.status", ReasonInvalidStatusRange},
				{SeverityError, "spec.routes[0].responseClasses[0].condition.status.min", ReasonInvalidStatusRange},
			},
		},
		{
			name: "missing response class condition",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  routes:
  - name: r
    condition: {method: GET}
    responseClasses:
    - {}
`,
			expected: []diagKey{
				{SeverityError, "spec.routes[0].responseClasses[0].condition", ReasonRequired},
			},
		},
		{
			name: "retry budget errors",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  retryBudget:
    retryRatio: -0.2
`,
			expected: []diagKey{
				{SeverityError, "spec.retryBudget.retryRatio", ReasonNegativeValue},
				{SeverityError, "spec.retryBudget.ttl", ReasonRequired},
			},
		},
		{
			name: "retry budget invalid ttl",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  retryBudget:
    ttl: soon
`,
			expected: []diagKey{
				{SeverityError, "spec.retryBudget.ttl", ReasonInvalidDuration},
			},
		},
		{
			name: "null dst override",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  dstOverrides:
  -
`,
			expected: []diagKey{
				{SeverityError, "spec.dstOverrides[0]", ReasonNullEntry},
			},
		},
		{
			name: "dst override invalid authority and port",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  dstOverrides:
  - authority: ""
    weight: "1"
  - authority: "bad host!:nope"
    weight: "1"
`,
			expected: []diagKey{
				{SeverityError, "spec.dstOverrides[0].authority", ReasonRequired},
				{SeverityError, "spec.dstOverrides[1].authority", ReasonInvalidAuthority},
				{SeverityError, "spec.dstOverrides[1].authority", ReasonInvalidPort},
			},
		},
		{
			name: "dst override zero and negative weight",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  dstOverrides:
  - authority: a.foo.svc.cluster.local
    weight: 0
  - authority: b.foo.svc.cluster.local
    weight: -1
`,
			expected: []diagKey{
				{SeverityError, "spec.dstOverrides[0].weight", ReasonRequired},
				{SeverityError, "spec.dstOverrides[1].weight", ReasonNegativeValue},
			},
		},
		{
			name: "cross namespace dst override warning",
			spec: `metadata:
  name: web.foo.svc.cluster.local
  namespace: foo
spec:
  dstOverrides:
  - authority: db.other.svc.cluster.local:80
    weight: "1"
`,
			expected: []diagKey{
				{SeverityWarning, "spec.dstOverrides[0].authority", ReasonBackendCrossNamespace},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := "apiVersion: linkerd.io/v1alpha2\nkind: ServiceProfile\n" + tc.spec
			report := mustValidate(t, doc)
			assertDiags(t, report, tc.expected)
		})
	}
}

const (
	routeA = `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: route-a
  namespace: foo
  creationTimestamp: "2024-01-01T00:00:00Z"
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - method: GET
      path:
        type: PathPrefix
        value: /x
    backendRefs:
    - group: ""
      kind: Service
      name: web
      port: 8080
`
	routeB = `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: route-b
  namespace: foo
  creationTimestamp: "2024-02-01T00:00:00Z"
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - method: GET
      path:
        type: PathPrefix
        value: /x
    backendRefs:
    - group: ""
      kind: Service
      name: web
      port: 8080
`
	routeBDisjoint = `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: route-b
  namespace: foo
  creationTimestamp: "2024-02-01T00:00:00Z"
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - method: POST
      path:
        type: PathPrefix
        value: /y
    backendRefs:
    - group: ""
      kind: Service
      name: web
      port: 8080
`
)

func TestHTTPRouteMerge(t *testing.T) {
	t.Run("conflicting equal matches across routes", func(t *testing.T) {
		report := mustValidate(t, routeA+"---\n"+routeB)
		if !hasDiag(report, "spec.rules[0].matches[0]", ReasonConflictingRouteMatch, SeverityWarning) {
			t.Fatalf("expected conflict on the younger route, got %+v", report.Diagnostics())
		}
		// The older route must not be flagged.
		for _, d := range report.Diagnostics() {
			if d.Resource.Name == "route-a" && d.Reason == ReasonConflictingRouteMatch {
				t.Fatalf("the older route must win precedence: %+v", d)
			}
		}
	})

	t.Run("disjoint matches merge cleanly", func(t *testing.T) {
		report := mustValidate(t, routeA+"---\n"+routeBDisjoint)
		for _, d := range report.Diagnostics() {
			if d.Reason == ReasonConflictingRouteMatch {
				t.Fatalf("unexpected merge conflict for disjoint matches: %+v", d)
			}
		}
	})

	t.Run("duplicate matches within one route", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: route-dup
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - path:
        value: /z
    backendRefs:
    - name: web
      port: 8080
  - matches:
    - path:
        value: /z
    backendRefs:
    - name: web
      port: 8080
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.rules[1].matches[0]", ReasonConflictingRouteMatch, SeverityWarning) {
			t.Fatalf("expected later rule within the same route to conflict, got %+v", report.Diagnostics())
		}
	})

	t.Run("default matches also participate in the merge", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: route-default
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - backendRefs:
    - name: web
      port: 8080
` + "---\n" + routeB
		report := mustValidate(t, doc)
		// The explicit /x match does not collide with the default "/" match.
		for _, d := range report.Diagnostics() {
			if d.Reason == ReasonConflictingRouteMatch {
				t.Fatalf("default prefix match must not conflict with /x: %+v", d)
			}
		}
	})
}

func TestHTTPRouteCrossNamespace(t *testing.T) {
	route := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: consumer
  namespace: ns-a
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: local
  rules:
  - matches:
    - path: {value: /}
    backendRefs:
    - group: ""
      kind: Service
      name: remote
      namespace: ns-b
      port: 80
`

	t.Run("cross namespace backend without grant", func(t *testing.T) {
		report := mustValidate(t, route)
		if !hasDiag(report, "spec.rules[0].backendRefs[0].namespace", ReasonBackendCrossNamespace, SeverityError) {
			t.Fatalf("expected cross-namespace backend error, got %+v", report.Diagnostics())
		}
	})

	grant := `apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-ns-a
  namespace: ns-b
spec:
  from:
  - group: policy.linkerd.io
    kind: HTTPRoute
    namespace: ns-a
  to:
  - group: ""
    kind: Service
`
	t.Run("cross namespace backend allowed by grant", func(t *testing.T) {
		report := mustValidate(t, route+"---\n"+grant)
		for _, d := range report.Diagnostics() {
			if d.Reason == ReasonBackendCrossNamespace && d.Severity == SeverityError {
				t.Fatalf("grant must permit the cross-namespace backend: %+v", d)
			}
		}
	})

	t.Run("grant in another namespace does not apply", func(t *testing.T) {
		wrongGrant := strings.Replace(grant, "namespace: ns-b", "namespace: ns-c", 1)
		report := mustValidate(t, route+"---\n"+wrongGrant)
		if !hasDiag(report, "spec.rules[0].backendRefs[0].namespace", ReasonBackendCrossNamespace, SeverityError) {
			t.Fatalf("grant in ns-c must not permit a backend in ns-b, got %+v", report.Diagnostics())
		}
	})

	t.Run("cross namespace server parent is rejected", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: inbound
  namespace: ns-a
spec:
  parentRefs:
  - group: policy.linkerd.io
    kind: Server
    name: srv
    namespace: ns-b
    sectionName: http
    port: 8080
  rules:
  - matches:
    - path: {value: /}
`
		report := mustValidate(t, doc)
		assertDiags(t, report, []diagKey{
			{SeverityError, "spec.parentRefs[0].namespace", ReasonParentCrossNamespace},
			{SeverityError, "spec.parentRefs[0].port", ReasonParentSpecifiesPort},
			{SeverityError, "spec.parentRefs[0].sectionName", ReasonParentSpecifiesSection},
		})
	})

	t.Run("cross namespace service parent is a warning", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: consumer-route
  namespace: ns-a
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: remote
    namespace: ns-b
  rules:
  - matches:
    - path: {value: /}
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.parentRefs[0].namespace", ReasonParentCrossNamespace, SeverityWarning) {
			t.Fatalf("expected consumer route warning, got %+v", report.Diagnostics())
		}
	})
}

func TestHTTPRouteRulesAndTimeouts(t *testing.T) {
	t.Run("missing backend port and unsupported kind", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - backendRefs:
    - name: web
    - kind: ConfigMap
      name: map
      port: 80
`
		report := mustValidate(t, doc)
		assertDiags(t, report, []diagKey{
			{SeverityError, "spec.rules[0].backendRefs[0]", ReasonBackendPortRequired},
			{SeverityError, "spec.rules[0].backendRefs[1].kind", ReasonUnsupportedBackend},
		})
	})

	t.Run("negative and all-zero weights", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - backendRefs:
    - name: a
      port: 80
      weight: 0
    - name: b
      port: 80
      weight: 0
  - backendRefs:
    - name: c
      port: 80
      weight: -5
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.rules[0].backendRefs", ReasonInvalidWeight, SeverityWarning) {
			t.Fatalf("expected all-zero weight warning, got %+v", report.Diagnostics())
		}
		if !hasDiag(report, "spec.rules[1].backendRefs[0].weight", ReasonInvalidWeight, SeverityError) {
			t.Fatalf("expected negative weight error, got %+v", report.Diagnostics())
		}
	})

	t.Run("unsupported filter and match values", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - path:
        type: Exact
        value: noslash
      method: WAT
    filters:
    - type: RequestMirror
`
		report := mustValidate(t, doc)
		assertDiags(t, report, []diagKey{
			{SeverityError, "spec.rules[0].filters[0].type", ReasonUnsupportedFilter},
			{SeverityError, "spec.rules[0].matches[0].method", ReasonUnsupportedValue},
			{SeverityError, "spec.rules[0].matches[0].path.value", ReasonInvalidMatch},
		})
	})

	t.Run("invalid regex is rejected", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - path:
        type: RegularExpression
        value: "["
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.rules[0].matches[0].path.value", ReasonInvalidMatch, SeverityError) {
			t.Fatalf("expected regex compile error, got %+v", report.Diagnostics())
		}
	})

	t.Run("timeout ordering", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - timeouts:
      request: 1s
      backendRequest: 10s
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.rules[0].timeouts.backendRequest", ReasonTimeoutExceedsRequest, SeverityError) {
			t.Fatalf("expected timeout ordering error, got %+v", report.Diagnostics())
		}
	})

	t.Run("malformed timeout keeps a stable path", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - timeouts:
      request: soon
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.rules[0].timeouts.request", ReasonInvalidDuration, SeverityError) {
			t.Fatalf("expected path-based duration error, got %+v", report.Diagnostics())
		}
		for _, d := range report.Diagnostics() {
			if d.Reason == ReasonInvalidDocument {
				t.Fatalf("malformed duration must not produce a generic document error: %+v", d)
			}
		}
	})

	t.Run("no parents and invalid name", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: INVALID
  namespace: foo
spec:
  rules:
  - matches:
    - path: {value: /}
`
		report := mustValidate(t, doc)
		assertDiags(t, report, []diagKey{
			{SeverityError, "metadata.name", ReasonInvalidName},
			{SeverityWarning, "spec.parentRefs", ReasonNoParentRefs},
		})
	})

	t.Run("duplicate parent refs", func(t *testing.T) {
		doc := `apiVersion: policy.linkerd.io/v1beta3
kind: HTTPRoute
metadata:
  name: r
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  - group: ""
    kind: Service
    name: web
  rules:
  - matches:
    - path: {value: /}
`
		report := mustValidate(t, doc)
		if !hasDiag(report, "spec.parentRefs[1]", ReasonDuplicateParentRef, SeverityWarning) {
			t.Fatalf("expected duplicate parent ref warning, got %+v", report.Diagnostics())
		}
	})
}

func TestGatewayAPIHTTPRouteAndUnknownKind(t *testing.T) {
	docs := `apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: gateway-route
  namespace: foo
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: web
  rules:
  - backendRefs:
    - name: web
---
apiVersion: example.com/v1
kind: SomethingElse
metadata:
  name: retained
  namespace: foo
spec:
  unknown: true
`
	report := mustValidate(t, docs)

	if len(report.Snapshot().Objects) != 2 {
		t.Fatalf("both documents must be retained, got %d", len(report.Snapshot().Objects))
	}
	if report.Snapshot().Objects[0].Route == nil {
		t.Fatal("gateway.networking.k8s.io HTTPRoute must decode into the typed route")
	}
	// The gateway route references a Service without a port, which the
	// destination policy would reject.
	if !hasDiag(report, "spec.rules[0].backendRefs[0]", ReasonBackendPortRequired, SeverityError) {
		t.Fatalf("expected missing-port diagnostic for gateway HTTPRoute, got %+v", report.Diagnostics())
	}
	// The unknown object is retained verbatim and never diagnosed as an
	// unknown-field/unknown-kind error.
	rawDocs, err := report.Documents()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawDocs[1]), `"unknown": true`) {
		t.Fatalf("unknown-kind document must be retained:\n%s", rawDocs[1])
	}
	for _, d := range report.Diagnostics() {
		if d.Resource.Name == "retained" {
			t.Fatalf("unknown object kinds must not be rejected: %+v", d)
		}
	}
}

func TestDeterministicDiagnostics(t *testing.T) {
	docs := validServiceProfile + "---\n" + routeA + "---\n" + routeB + `---
apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: bad.foo.svc.cluster.local
  namespace: wrong
spec:
  routes:
  - condition: {}
`
	first := mustValidate(t, docs)
	second := mustValidate(t, docs)

	firstJSON, _ := json.Marshal(first.Diagnostics())
	secondJSON, _ := json.Marshal(second.Diagnostics())
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("diagnostics are not stable:\n%s\nvs\n%s", firstJSON, secondJSON)
	}
}
