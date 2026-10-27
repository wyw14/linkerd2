package offline

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	spv1a2 "github.com/linkerd/linkerd2/controller/gen/apis/serviceprofile/v1alpha2"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	minHTTPStatus = 100
	maxHTTPStatus = 599
	// decimilliWeightDivisor mirrors the destination service: weights are
	// expressed in decimillis, 10_000 being 100%.
	decimilliWeightFactor = 10
)

// validateProfile checks a ServiceProfile against the semantics independently
// enforced by the sp-validator webhook and the destination service's profile
// translator.
func (v *validator) validateProfile(obj *Object) {
	profile := obj.Profile

	if errs := validation.IsDNS1123Subdomain(profile.Name); len(errs) > 0 {
		v.add(obj, "metadata.name", ReasonInvalidName,
			fmt.Sprintf("invalid ServiceProfile name %q: %s", profile.Name, errs[0]), SeverityError)
	}
	v.validateProfileNamespace(obj, profile)

	routeNames := make(map[string]int)
	routesPath := "spec.routes"
	for i, route := range profile.Spec.Routes {
		routePath := at(routesPath, i)
		if route == nil {
			v.add(obj, routePath, ReasonNullEntry, "route entry must not be null", SeverityError)
			continue
		}
		v.validateRoute(obj, routePath, i, route, routeNames)
	}

	v.validateRetryBudget(obj, profile.Spec.RetryBudget)
	v.validateDstOverrides(obj, profile)
}

// validateProfileNamespace verifies that the FQDN encoded in the
// ServiceProfile name (which is how the destination service selects it)
// agrees with metadata.namespace.
func (v *validator) validateProfileNamespace(obj *Object, profile *spv1a2.ServiceProfile) {
	if profile.Namespace == "" {
		return
	}
	_, ns, ok := authorityServiceAndNamespace(profile.Name)
	if ok && ns != profile.Namespace {
		v.add(obj, "metadata.name", ReasonNamespaceMismatch,
			fmt.Sprintf("ServiceProfile name %q selects namespace %q but metadata.namespace is %q; the destination service selects profiles by FQDN",
				profile.Name, ns, profile.Namespace), SeverityWarning)
	}
}

func (v *validator) validateRoute(obj *Object, routePath string, routeIndex int, route *spv1a2.RouteSpec, names map[string]int) {
	if route.Name == "" {
		v.add(obj, field(routePath, "name"), ReasonRequired,
			"route must have a name; the destination service uses it as the route metrics label", SeverityError)
	} else if first, dup := names[route.Name]; dup {
		v.add(obj, field(routePath, "name"), ReasonDuplicateName,
			fmt.Sprintf("route name %q is already defined by spec.routes[%d]; duplicate route names collide in route metrics", route.Name, first), SeverityError)
	} else {
		names[route.Name] = routeIndex
	}

	if route.Timeout != "" {
		d, err := time.ParseDuration(route.Timeout)
		path := field(routePath, "timeout")
		switch {
		case err != nil:
			v.add(obj, path, ReasonInvalidDuration,
				fmt.Sprintf("invalid timeout %q: %s", route.Timeout, err), SeverityError)
		case d < 0:
			v.add(obj, path, ReasonNegativeDuration,
				fmt.Sprintf("timeout must be non-negative: %q", route.Timeout), SeverityError)
		}
	}

	if route.Condition == nil {
		v.add(obj, field(routePath, "condition"), ReasonRequired,
			"route must have a condition", SeverityError)
	} else {
		v.validateRequestMatch(obj, field(routePath, "condition"), route.Condition)
	}

	rcsPath := field(routePath, "responseClasses")
	for j, rc := range route.ResponseClasses {
		rcPath := at(rcsPath, j)
		if rc == nil {
			v.add(obj, rcPath, ReasonNullEntry, "response class entry must not be null", SeverityError)
			continue
		}
		if rc.Condition == nil {
			v.add(obj, field(rcPath, "condition"), ReasonRequired,
				"response class must have a condition", SeverityError)
			continue
		}
		v.validateResponseMatch(obj, field(rcPath, "condition"), rc.Condition)
	}
}

func (v *validator) validateRequestMatch(obj *Object, path string, m *spv1a2.RequestMatch) {
	hasField := false
	if m.All != nil {
		hasField = true
		childPath := field(path, "all")
		for i, child := range m.All {
			if child == nil {
				v.add(obj, at(childPath, i), ReasonNullEntry, "null condition \"all\"", SeverityError)
				continue
			}
			v.validateRequestMatch(obj, at(childPath, i), child)
		}
	}
	if m.Any != nil {
		hasField = true
		childPath := field(path, "any")
		for i, child := range m.Any {
			if child == nil {
				v.add(obj, at(childPath, i), ReasonNullEntry, "null condition \"any\"", SeverityError)
				continue
			}
			v.validateRequestMatch(obj, at(childPath, i), child)
		}
	}
	if m.Not != nil {
		hasField = true
		v.validateRequestMatch(obj, field(path, "not"), m.Not)
	}
	if m.Method != "" {
		hasField = true
	}
	if m.PathRegex != "" {
		hasField = true
	}
	if !hasField {
		v.add(obj, path, ReasonInvalidMatch,
			"a request match must have a field set", SeverityError)
	}
}

func (v *validator) validateResponseMatch(obj *Object, path string, m *spv1a2.ResponseMatch) {
	hasField := false
	if m.All != nil {
		hasField = true
		childPath := field(path, "all")
		for i, child := range m.All {
			if child == nil {
				v.add(obj, at(childPath, i), ReasonNullEntry, "null condition \"all\"", SeverityError)
				continue
			}
			v.validateResponseMatch(obj, at(childPath, i), child)
		}
	}
	if m.Any != nil {
		hasField = true
		childPath := field(path, "any")
		for i, child := range m.Any {
			if child == nil {
				v.add(obj, at(childPath, i), ReasonNullEntry, "null condition \"any\"", SeverityError)
				continue
			}
			v.validateResponseMatch(obj, at(childPath, i), child)
		}
	}
	if m.Not != nil {
		hasField = true
		v.validateResponseMatch(obj, field(path, "not"), m.Not)
	}
	if m.Status != nil {
		hasField = true
		v.validateStatusRange(obj, field(path, "status"), m.Status.Min, m.Status.Max)
	}
	if !hasField {
		v.add(obj, path, ReasonInvalidMatch,
			"a response match must have a field set", SeverityError)
	}
}

func (v *validator) validateStatusRange(obj *Object, path string, min, max uint32) {
	if min != 0 && (min < minHTTPStatus || min > maxHTTPStatus) {
		v.add(obj, field(path, "min"), ReasonInvalidStatusRange,
			fmt.Sprintf("range minimum must be between %d and %d, inclusive", minHTTPStatus, maxHTTPStatus), SeverityError)
	}
	if max != 0 && (max < minHTTPStatus || max > maxHTTPStatus) {
		v.add(obj, field(path, "max"), ReasonInvalidStatusRange,
			fmt.Sprintf("range maximum must be between %d and %d, inclusive", minHTTPStatus, maxHTTPStatus), SeverityError)
	}
	if min != 0 && max != 0 && max < min {
		v.add(obj, path, ReasonInvalidStatusRange,
			"range maximum cannot be smaller than minimum", SeverityError)
	}
}

func (v *validator) validateRetryBudget(obj *Object, rb *spv1a2.RetryBudget) {
	if rb == nil {
		return
	}
	budgetPath := "spec.retryBudget"
	if rb.RetryRatio < 0 {
		v.add(obj, field(budgetPath, "retryRatio"), ReasonNegativeValue,
			fmt.Sprintf("retryRatio must be non-negative: %f", rb.RetryRatio), SeverityError)
	}
	ttlPath := field(budgetPath, "ttl")
	if rb.TTL == "" {
		v.add(obj, ttlPath, ReasonRequired,
			"retryBudget missing ttl field", SeverityError)
		return
	}
	d, err := time.ParseDuration(rb.TTL)
	switch {
	case err != nil:
		v.add(obj, ttlPath, ReasonInvalidDuration,
			fmt.Sprintf("invalid retryBudget ttl %q: %s", rb.TTL, err), SeverityError)
	case d < 0:
		v.add(obj, ttlPath, ReasonNegativeDuration,
			fmt.Sprintf("retryBudget ttl must be non-negative: %q", rb.TTL), SeverityError)
	}
}

func (v *validator) validateDstOverrides(obj *Object, profile *spv1a2.ServiceProfile) {
	overridesPath := "spec.dstOverrides"
	for i, dst := range profile.Spec.DstOverrides {
		dstPath := at(overridesPath, i)
		if dst == nil {
			v.add(obj, dstPath, ReasonNullEntry, "dstOverride entry must not be null", SeverityError)
			continue
		}
		authorityPath := field(dstPath, "authority")
		if dst.Authority == "" {
			v.add(obj, authorityPath, ReasonRequired,
				"dstOverride must have an authority", SeverityError)
		} else {
			v.validateAuthority(obj, authorityPath, profile.Namespace, dst.Authority)
		}
		v.validateDstWeight(obj, field(dstPath, "weight"), dst)
	}
}

// validateAuthority mirrors the destination service's toDstOverrides parsing:
// the authority may be a host or a host:port, and traffic split backends are
// addressed by DNS name (or IP).
func (v *validator) validateAuthority(obj *Object, path, profileNamespace, authority string) {
	host := authority
	port := ""
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host = h
		port = p
	}

	if host == "" {
		v.add(obj, path, ReasonInvalidAuthority,
			fmt.Sprintf("authority %q must contain a host", authority), SeverityError)
	} else if net.ParseIP(host) == nil {
		if errs := validation.IsDNS1123Subdomain(host); len(errs) > 0 {
			v.add(obj, path, ReasonInvalidAuthority,
				fmt.Sprintf("authority %q has an invalid host: %s", authority, errs[0]), SeverityError)
		}
	}

	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			v.add(obj, path, ReasonInvalidPort,
				fmt.Sprintf("authority %q has an invalid port: must be between 1 and 65535", authority), SeverityError)
		}
	}

	// Cross-namespace dstOverrides are allowed (the destination service
	// resolves authorities cluster-wide) but cannot be confirmed offline.
	if _, ns, ok := authorityServiceAndNamespace(host); ok && profileNamespace != "" && ns != profileNamespace {
		v.add(obj, path, ReasonBackendCrossNamespace,
			fmt.Sprintf("dstOverride references a backend in namespace %q while the ServiceProfile is in %q; cross-namespace backends are allowed but cannot be resolved offline",
				ns, profileNamespace), SeverityWarning)
	}
}

func (v *validator) validateDstWeight(obj *Object, path string, dst *spv1a2.WeightedDst) {
	switch dst.Weight.Sign() {
	case 0:
		v.add(obj, path, ReasonRequired,
			"dstOverride weight is required and must be greater than zero", SeverityError)
	case -1:
		v.add(obj, path, ReasonNegativeValue,
			"dstOverride weight must be greater than zero", SeverityError)
	default:
		// The destination service converts the milli value into a uint32
		// decimilli weight; reject values that would overflow.
		if dst.Weight.MilliValue() > int64(math.MaxUint32/decimilliWeightFactor) {
			v.add(obj, path, ReasonInvalidWeight,
				fmt.Sprintf("dstOverride weight %s is too large: it overflows the proxy decimilli weight", dst.Weight.String()), SeverityError)
		}
	}
}

// authorityServiceAndNamespace extracts the service name and namespace from a
// Kubernetes service DNS name in either "<service>.<namespace>" or
// "<service>.<namespace>.svc[.<cluster-domain>]" form.
func authorityServiceAndNamespace(host string) (service, namespace string, ok bool) {
	labels := strings.Split(host, ".")
	switch {
	case len(labels) >= 3 && labels[2] == "svc":
		return labels[0], labels[1], true
	case len(labels) == 2:
		return labels[0], labels[1], true
	default:
		return "", "", false
	}
}
