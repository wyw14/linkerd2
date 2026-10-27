// Package offline provides side-effect-free, offline validation of Linkerd
// ServiceProfile route configuration and the HTTPRoute resources that the
// policy controller merges onto Services.
//
// The validation mirrors the requirements enforced independently by the
// controller's sp-validator admission webhook, the destination service's
// profile translator and the policy controller's route index:
//
//   - route names, conditions and timeouts,
//   - retry budgets,
//   - backend references (ServiceProfile dstOverrides and HTTPRoute
//     backendRefs), including cross-namespace references governed by
//     ReferenceGrant,
//   - HTTPRoute attachment/merge conflicts.
//
// No data-plane connection is opened and no Kubernetes object is read from or
// written to a cluster: every input must be provided as an in-memory Snapshot.
// Unknown fields are never rejected; the original documents are retained and
// returned verbatim.
package offline

import (
	"encoding/json"
	"sort"
)

// Severity classifies a Diagnostic.
type Severity string

const (
	// SeverityError describes a configuration that one of the control-plane
	// components would reject or translate into a runtime failure.
	SeverityError Severity = "Error"
	// SeverityWarning describes a configuration that is accepted but likely
	// wrong or impossible to verify offline.
	SeverityWarning Severity = "Warning"
)

// Stable, machine-readable diagnostic reason codes.
const (
	// ReasonInvalidDocument covers documents that cannot be decoded into the
	// expected type (e.g. a duration field with the wrong JSON type).
	ReasonInvalidDocument = "InvalidDocument"
	// ReasonInvalidName covers names that are not valid RFC 1123 subdomains.
	ReasonInvalidName = "InvalidName"
	// ReasonRequired covers missing, mandatory fields.
	ReasonRequired = "Required"
	// ReasonNullEntry covers null entries inside array fields.
	ReasonNullEntry = "NullEntry"
	// ReasonDuplicateName covers route names that collide within a profile.
	ReasonDuplicateName = "DuplicateName"
	// ReasonInvalidDuration covers values that time.ParseDuration rejects.
	ReasonInvalidDuration = "InvalidDuration"
	// ReasonNegativeDuration covers negative durations.
	ReasonNegativeDuration = "NegativeDuration"
	// ReasonInvalidMatch covers request/response matches without a field set.
	ReasonInvalidMatch = "InvalidMatch"
	// ReasonInvalidStatusRange covers out-of-range or inverted status ranges.
	ReasonInvalidStatusRange = "InvalidStatusRange"
	// ReasonNegativeValue covers negative numeric values.
	ReasonNegativeValue = "NegativeValue"
	// ReasonInvalidAuthority covers malformed dstOverride authorities.
	ReasonInvalidAuthority = "InvalidAuthority"
	// ReasonInvalidPort covers missing or out-of-range ports.
	ReasonInvalidPort = "InvalidPort"
	// ReasonInvalidWeight covers missing, negative, zero or overflowing
	// backend weights.
	ReasonInvalidWeight = "InvalidWeight"
	// ReasonBackendCrossNamespace covers cross-namespace backend references
	// that are not permitted by a ReferenceGrant.
	ReasonBackendCrossNamespace = "BackendCrossNamespace"
	// ReasonNamespaceMismatch covers a profile name whose namespace label
	// disagrees with metadata.namespace.
	ReasonNamespaceMismatch = "NamespaceMismatch"
	// ReasonUnsupportedValue covers enum values the control plane does not
	// understand (match types, methods, filter types, ...).
	ReasonUnsupportedValue = "UnsupportedValue"
	// ReasonUnsupportedFilter covers filters the policy controller rejects
	// (RequestMirror, ExtensionRef, ...).
	ReasonUnsupportedFilter = "UnsupportedFilter"
	// ReasonUnsupportedBackend covers backendRefs to unsupported resource
	// kinds.
	ReasonUnsupportedBackend = "UnsupportedBackend"
	// ReasonBackendPortRequired covers Service backendRefs without a port.
	ReasonBackendPortRequired = "BackendPortRequired"
	// ReasonParentCrossNamespace covers parentRefs crossing a namespace
	// boundary without an offline-provided allowance.
	ReasonParentCrossNamespace = "ParentCrossNamespace"
	// ReasonParentSpecifiesPort covers Server parentRefs that select a port.
	ReasonParentSpecifiesPort = "ParentSpecifiesPort"
	// ReasonParentSpecifiesSection covers Server parentRefs that select a
	// section name.
	ReasonParentSpecifiesSection = "ParentSpecifiesSection"
	// ReasonDuplicateParentRef covers the same parent being referenced twice.
	ReasonDuplicateParentRef = "DuplicateParentRef"
	// ReasonNoParentRefs covers HTTPRoutes that attach to no parent.
	ReasonNoParentRefs = "NoParentRefs"
	// ReasonConflictingRouteMatch covers equal matches contributed by
	// different merged HTTPRoutes, per Gateway API precedence rules.
	ReasonConflictingRouteMatch = "ConflictingRouteMatch"
	// ReasonTimeoutExceedsRequest covers backendRequest timeouts greater than
	// the request timeout.
	ReasonTimeoutExceedsRequest = "TimeoutExceedsRequest"
)

// ResourceRef identifies the Kubernetes object a Diagnostic belongs to.
type ResourceRef struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Diagnostic is a single validation finding. Path is a stable, JSONPath-style
// field path relative to the referenced object, e.g.
// "spec.routes[0].responseClasses[1].condition.status.max".
type Diagnostic struct {
	Resource ResourceRef `json:"resource"`
	Path     string      `json:"path"`
	Severity Severity    `json:"severity"`
	Reason   string      `json:"reason"`
	Message  string      `json:"message"`
}

// Report is the result of an offline validation run.
type Report struct {
	snapshot    *Snapshot
	diagnostics []*Diagnostic
}

// Snapshot returns the validated Snapshot, including documents that carried
// unknown fields.
func (r *Report) Snapshot() *Snapshot {
	return r.snapshot
}

// Diagnostics returns all diagnostics sorted by object reference and path so
// that repeated runs over identical inputs produce an identical ordering.
func (r *Report) Diagnostics() []*Diagnostic {
	out := make([]*Diagnostic, len(r.diagnostics))
	copy(out, r.diagnostics)
	sort.SliceStable(out, func(i, j int) bool {
		return diagnosticKey(out[i]) < diagnosticKey(out[j])
	})
	return out
}

// BySeverity returns the diagnostics of the given severity, in the same stable
// order as Diagnostics.
func (r *Report) BySeverity(severity Severity) []*Diagnostic {
	var out []*Diagnostic
	for _, d := range r.Diagnostics() {
		if d.Severity == severity {
			out = append(out, d)
		}
	}
	return out
}

// HasErrors reports whether the report contains any error diagnostic.
func (r *Report) HasErrors() bool {
	for _, d := range r.diagnostics {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Documents returns the retained input documents as indented JSON. Unknown
// fields are preserved because decoding is intentionally lenient.
func (r *Report) Documents() ([][]byte, error) {
	docs := make([][]byte, 0, len(r.snapshot.Objects))
	for _, obj := range r.snapshot.Objects {
		data, err := json.MarshalIndent(obj.Raw, "", "  ")
		if err != nil {
			return nil, err
		}
		docs = append(docs, data)
	}
	return docs, nil
}

func diagnosticKey(d *Diagnostic) string {
	return d.Resource.Namespace + "\x00" +
		d.Resource.Group + "\x00" +
		d.Resource.Kind + "\x00" +
		d.Resource.Name + "\x00" +
		d.Path + "\x00" +
		d.Reason + "\x00" +
		d.Message
}

// field joins a base path with a field name: field("spec", "routes") ->
// "spec.routes"; field("", "spec") -> "spec".
func field(base, name string) string {
	if base == "" {
		return name
	}
	return base + "." + name
}

// at indexes a list path: at("spec.routes", 2) -> "spec.routes[2]".
func at(base string, index int) string {
	return joinIndex(base, index)
}

func joinIndex(base string, index int) string {
	return base + "[" + itoa(index) + "]"
}

// itoa avoids pulling in strconv for a single call site in path building;
// strconv is imported in the files that need richer conversions.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
