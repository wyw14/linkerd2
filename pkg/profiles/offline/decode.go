package offline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	policyv1b3 "github.com/linkerd/linkerd2/controller/gen/apis/policy/v1beta3"
	spv1a2 "github.com/linkerd/linkerd2/controller/gen/apis/serviceprofile/v1alpha2"
	yamlDecoder "k8s.io/apimachinery/pkg/util/yaml"
	gatewayv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

const (
	serviceProfileKind = "ServiceProfile"
	httpRouteKind      = "HTTPRoute"
	referenceGrantKind = "ReferenceGrant"

	linkerdGroup   = "linkerd.io"
	policyGroup    = "policy.linkerd.io"
	gatewayGroup   = "gateway.networking.k8s.io"
	coreGroup      = ""
	serverKind     = "Server"
	serviceKind    = "Service"
	egressKind     = "EgressNetwork"
	defaultCluster = "cluster.local"
)

// Object is a single decoded document. Raw always retains the complete
// document, including unknown fields. At most one of the typed pointers is
// populated; decodeError is set when the document could not be decoded into
// its typed representation.
type Object struct {
	Ref ResourceRef
	Raw map[string]any

	Profile *spv1a2.ServiceProfile
	Route   *policyv1b3.HTTPRoute
	Grant   *gatewayv1a2.ReferenceGrant

	decodeError error
}

// Snapshot is an in-memory set of objects validated together. It never
// contacts the Kubernetes API or the data plane.
type Snapshot struct {
	// Objects retains every decoded document in input order, including
	// documents of unsupported kinds and documents with unknown fields.
	Objects []*Object

	// ClusterDomain is used to interpret ServiceProfile authorities. It
	// defaults to cluster.local.
	ClusterDomain string

	serviceProfiles []*Object
	httpRoutes      []*Object
	referenceGrants []*Object
}

// DecodeSnapshot parses YAML or JSON bytes, which may contain several YAML
// documents separated by "---", into a Snapshot. Decoding is deliberately
// lenient: unknown fields are retained and never reported. Type errors are
// surfaced as path-based diagnostics when Validate runs.
func DecodeSnapshot(data []byte) (*Snapshot, error) {
	s := &Snapshot{ClusterDomain: defaultCluster}
	dec := yamlDecoder.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to decode route configuration document: %w", err)
		}
		// Skip empty documents produced by trailing "---" separators.
		if len(raw) == 0 {
			continue
		}
		s.addRaw(raw)
	}
	return s, nil
}

// ValidateBytes decodes and validates the given documents in one step.
func ValidateBytes(data []byte) (*Report, error) {
	s, err := DecodeSnapshot(data)
	if err != nil {
		return nil, err
	}
	return s.Validate(), nil
}

func (s *Snapshot) addRaw(raw map[string]any) {
	group, kind := gvk(raw)
	ref := ResourceRef{
		Group:     group,
		Kind:      kind,
		Namespace: stringAt(raw, "metadata", "namespace"),
		Name:      stringAt(raw, "metadata", "name"),
	}
	obj := &Object{Ref: ref, Raw: raw}

	rawJSON, err := json.Marshal(raw)
	if err != nil {
		obj.decodeError = err
		s.Objects = append(s.Objects, obj)
		return
	}

	switch {
	case kind == serviceProfileKind && group == linkerdGroup:
		typed := &spv1a2.ServiceProfile{}
		if err := json.Unmarshal(rawJSON, typed); err != nil {
			obj.decodeError = err
		} else {
			obj.Profile = typed
			obj.Ref.Namespace = typed.Namespace
			obj.Ref.Name = typed.Name
			s.serviceProfiles = append(s.serviceProfiles, obj)
		}
	case kind == httpRouteKind && (group == policyGroup || group == gatewayGroup):
		// The policy.linkerd.io/v1beta3 HTTPRoute is a compatible superset of
		// the Gateway API HTTPRoute for the fields the control plane uses.
		typed := &policyv1b3.HTTPRoute{}
		if err := json.Unmarshal(rawJSON, typed); err != nil {
			obj.decodeError = err
		} else {
			obj.Route = typed
			obj.Ref.Namespace = typed.Namespace
			obj.Ref.Name = typed.Name
			s.httpRoutes = append(s.httpRoutes, obj)
		}
	case kind == referenceGrantKind && group == gatewayGroup:
		typed := &gatewayv1a2.ReferenceGrant{}
		if err := json.Unmarshal(rawJSON, typed); err != nil {
			obj.decodeError = err
		} else {
			obj.Grant = typed
			obj.Ref.Namespace = typed.Namespace
			obj.Ref.Name = typed.Name
			s.referenceGrants = append(s.referenceGrants, obj)
		}
	}

	s.Objects = append(s.Objects, obj)
}

// Validate validates every decoded object and the cross-object relationships
// (HTTPRoute merges, cross-namespace references and ReferenceGrants). The
// report is deterministic: it never performs I/O and mutates no state.
func (s *Snapshot) Validate() *Report {
	if s.ClusterDomain == "" {
		s.ClusterDomain = defaultCluster
	}
	v := &validator{snapshot: s}

	for _, obj := range s.Objects {
		// Timeouts are validated against the retained raw document so that
		// malformed durations still produce precise path diagnostics even
		// when typed decoding fails.
		preciseTimeoutDiagnostics := 0
		if obj.Ref.Kind == httpRouteKind {
			preciseTimeoutDiagnostics = len(v.diagnostics)
			v.validateRawRouteTimeouts(obj)
			preciseTimeoutDiagnostics = len(v.diagnostics) - preciseTimeoutDiagnostics
		}
		v.validateDecode(obj, preciseTimeoutDiagnostics > 0)
		switch {
		case obj.Profile != nil:
			v.validateProfile(obj)
		case obj.Route != nil:
			v.validateHTTPRoute(obj)
		}
	}
	v.validateHTTPRouteMerge()

	return &Report{snapshot: s, diagnostics: v.diagnostics}
}

type validator struct {
	snapshot    *Snapshot
	diagnostics []*Diagnostic
}

func (v *validator) add(obj ObjectLike, path, reason, message string, severity Severity) {
	v.diagnostics = append(v.diagnostics, &Diagnostic{
		Resource: obj.ObjectRef(),
		Path:     path,
		Severity: severity,
		Reason:   reason,
		Message:  message,
	})
}

// ObjectLike is implemented by every decodable, referenceable object.
type ObjectLike interface {
	ObjectRef() ResourceRef
}

func (o *Object) ObjectRef() ResourceRef { return o.Ref }

func gvk(raw map[string]any) (group, kind string) {
	apiVersion := stringAt(raw, "apiVersion")
	kind = stringAt(raw, "kind")
	if idx := indexByte(apiVersion, '/'); idx >= 0 {
		return apiVersion[:idx], kind
	}
	return apiVersion, kind
}

func stringAt(raw map[string]any, path ...string) string {
	var cur any = raw
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[p]
		if !ok {
			return ""
		}
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
