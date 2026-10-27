package offline

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	policyv1b3 "github.com/linkerd/linkerd2/controller/gen/apis/policy/v1beta3"
	"k8s.io/apimachinery/pkg/util/validation"
	gatewayv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// supportedHTTPRouteFilterTypes are the HTTPRoute filter types that the Linkerd
// policy controller implements; any other type prevents the route from being
// admitted.
var supportedHTTPRouteFilterTypes = map[string]struct{}{
	string(policyv1b3.HTTPRouteFilterRequestHeaderModifier): {},
	"ResponseHeaderModifier":                                {},
	string(policyv1b3.HTTPRouteFilterRequestRedirect):       {},
}

// validateDecode reports typed decode errors as path-based diagnostics. The
// generic Raw document remains available so unknown fields are retained.
// When the decode failure is already covered by precise raw-document
// diagnostics (malformed timeout durations), the generic diagnostic is
// suppressed to avoid duplicate findings.
func (v *validator) validateDecode(obj *Object, coveredByRawDiagnostics bool) {
	if obj.decodeError == nil {
		return
	}
	if coveredByRawDiagnostics && strings.Contains(obj.decodeError.Error(), "invalid duration") {
		return
	}
	path := ""
	message := obj.decodeError.Error()
	var typeErr *json.UnmarshalTypeError
	if asUnmarshalTypeError(obj.decodeError, &typeErr) && typeErr.Field != "" {
		path = typeErr.Field
	}
	v.add(obj, path, ReasonInvalidDocument,
		fmt.Sprintf("invalid route configuration document: %s", message), SeverityError)
}

func asUnmarshalTypeError(err error, target **json.UnmarshalTypeError) bool {
	if t, ok := err.(*json.UnmarshalTypeError); ok {
		*target = t
		return true
	}
	return false
}

func (v *validator) validateHTTPRoute(obj *Object) {
	route := obj.Route

	if errs := validation.IsDNS1123Subdomain(route.Name); len(errs) > 0 {
		v.add(obj, "metadata.name", ReasonInvalidName,
			fmt.Sprintf("invalid HTTPRoute name %q: %s", route.Name, errs[0]), SeverityError)
	}

	v.validateParentRefs(obj, route)
	for i, rule := range route.Spec.Rules {
		v.validateHTTPRule(obj, at("spec.rules", i), route.Namespace, rule)
	}
}

type normalizedParentRef struct {
	group     string
	kind      string
	namespace string
	name      string
	section   string
	port      int32
}

func (v *validator) validateParentRefs(obj *Object, route *policyv1b3.HTTPRoute) {
	parentRefs := route.Spec.ParentRefs
	parentRefsPath := "spec.parentRefs"

	if len(parentRefs) == 0 {
		v.add(obj, parentRefsPath, ReasonNoParentRefs,
			"HTTPRoute has no parentRefs and will not be attached to any Service by the policy controller", SeverityWarning)
		return
	}

	seen := make(map[string]int)
	for i, ref := range parentRefs {
		refPath := at(parentRefsPath, i)
		normalized := normalizeParentRef(ref, route.Namespace)

		if dedupeKey := parentDedupeKey(normalized); dedupeKey != "" {
			if first, dup := seen[dedupeKey]; dup {
				v.add(obj, refPath, ReasonDuplicateParentRef,
					fmt.Sprintf("parent is already referenced by spec.parentRefs[%d]; referencing an identical parent more than once is invalid", first), SeverityWarning)
			} else {
				seen[dedupeKey] = i
			}
		}

		switch {
		case normalized.kind == serverKind:
			// Mirrors the policy controller's InvalidParentRef rules for
			// inbound routes targeting Servers.
			if ref.Namespace != nil && string(*ref.Namespace) != route.Namespace {
				v.add(obj, field(refPath, "namespace"), ReasonParentCrossNamespace,
					"HTTPRoute may not reference a parent Server in another namespace", SeverityError)
			}
			if ref.Port != nil {
				v.add(obj, field(refPath, "port"), ReasonParentSpecifiesPort,
					"HTTPRoute may not reference a parent Server by port", SeverityError)
			}
			if ref.SectionName != nil {
				v.add(obj, field(refPath, "sectionName"), ReasonParentSpecifiesSection,
					"HTTPRoute may not reference a parent Server by section name", SeverityError)
			}
		case normalized.kind == serviceKind:
			if normalized.group != coreGroup {
				v.add(obj, field(refPath, "group"), ReasonUnsupportedValue,
					fmt.Sprintf("only core (group %q) Service parents are supported, got group %q", "", normalized.group), SeverityError)
			}
			if ref.Namespace != nil && string(*ref.Namespace) != route.Namespace {
				// Mesh "consumer" routes are allowed, but their attachment
				// cannot be verified offline.
				v.add(obj, field(refPath, "namespace"), ReasonParentCrossNamespace,
					fmt.Sprintf("HTTPRoute references a parent Service in another namespace %q; consumer routes only apply to outbound traffic from namespace %q and cannot be verified offline",
						normalized.namespace, route.Namespace), SeverityWarning)
			}
		default:
			v.add(obj, field(refPath, "kind"), ReasonUnsupportedValue,
				fmt.Sprintf("unsupported parent kind %q; only Service and Server parents are supported", normalized.kind), SeverityError)
		}
	}
}

func normalizeParentRef(ref gatewayv1a2.ParentReference, routeNamespace string) normalizedParentRef {
	group := coreGroup
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	kind := serviceKind
	if ref.Kind != nil && string(*ref.Kind) != "" {
		kind = string(*ref.Kind)
	}
	namespace := routeNamespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}
	section := ""
	if ref.SectionName != nil {
		section = string(*ref.SectionName)
	}
	port := int32(0)
	if ref.Port != nil {
		port = int32(*ref.Port)
	}
	return normalizedParentRef{
		group:     group,
		kind:      kind,
		namespace: namespace,
		name:      string(ref.Name),
		section:   section,
		port:      port,
	}
}

func parentDedupeKey(p normalizedParentRef) string {
	if p.name == "" {
		return ""
	}
	return strings.Join([]string{p.group, p.kind, p.namespace, p.name, p.section, fmt.Sprint(p.port)}, "\x00")
}

func (v *validator) validateHTTPRule(obj *Object, rulePath, routeNamespace string, rule policyv1b3.HTTPRouteRule) {
	matchesPath := field(rulePath, "matches")
	for i, match := range rule.Matches {
		v.validateHTTPRouteMatch(obj, at(matchesPath, i), match)
	}

	filtersPath := field(rulePath, "filters")
	for i, filter := range rule.Filters {
		v.validateHTTPFilter(obj, at(filtersPath, i), string(filter.Type))
	}

	v.validateBackendRefs(obj, field(rulePath, "backendRefs"), routeNamespace, rule.BackendRefs)
}

func (v *validator) validateHTTPRouteMatch(obj *Object, path string, match policyv1b3.HTTPRouteMatch) {
	if match.Path != nil {
		pathMatch := match.Path
		pathPath := field(path, "path")
		matchType := policyv1b3.PathMatchPathPrefix
		if pathMatch.Type != nil {
			matchType = *pathMatch.Type
		}
		switch matchType {
		case policyv1b3.PathMatchExact, policyv1b3.PathMatchPathPrefix:
			if pathMatch.Value != nil {
				value := *pathMatch.Value
				if !strings.HasPrefix(value, "/") || strings.Contains(value, "//") {
					v.add(obj, field(pathPath, "value"), ReasonInvalidMatch,
						fmt.Sprintf("%s path values must start with '/' and must not contain consecutive '/' characters: %q", matchType, value), SeverityError)
				}
			}
		case policyv1b3.PathMatchRegularExpression:
			if pathMatch.Value != nil {
				if _, err := regexp.Compile(*pathMatch.Value); err != nil {
					v.add(obj, field(pathPath, "value"), ReasonInvalidMatch,
						fmt.Sprintf("invalid path regular expression %q: %s", *pathMatch.Value, err), SeverityError)
				}
			}
		default:
			v.add(obj, field(pathPath, "type"), ReasonUnsupportedValue,
				fmt.Sprintf("unsupported path match type %q", matchType), SeverityError)
		}
	}

	if match.Method != nil {
		switch *match.Method {
		case policyv1b3.HTTPMethodGet, policyv1b3.HTTPMethodHead, policyv1b3.HTTPMethodPost,
			policyv1b3.HTTPMethodPut, policyv1b3.HTTPMethodDelete, policyv1b3.HTTPMethodConnect,
			policyv1b3.HTTPMethodOptions, policyv1b3.HTTPMethodTrace, policyv1b3.HTTPMethodPatch:
		default:
			v.add(obj, field(path, "method"), ReasonUnsupportedValue,
				fmt.Sprintf("unsupported HTTP method %q", *match.Method), SeverityError)
		}
	}

	headersPath := field(path, "headers")
	for i, header := range match.Headers {
		v.validateHTTPHeader(obj, at(headersPath, i), string(header.Name), header.Value, header.Type)
	}
	queryPath := field(path, "queryParams")
	for i, query := range match.QueryParams {
		matchType := string(policyv1b3.QueryParamMatchExact)
		if query.Type != nil {
			matchType = string(*query.Type)
		}
		v.validateHTTPNameValue(obj, at(queryPath, i), "query parameter", query.Name, query.Value,
			matchType, string(policyv1b3.QueryParamMatchExact), string(policyv1b3.QueryParamMatchRegularExpression))
	}
}

func (v *validator) validateHTTPHeader(obj *Object, path, name, value string, matchType *policyv1b3.HeaderMatchType) {
	headerType := string(policyv1b3.HeaderMatchExact)
	if matchType != nil {
		headerType = string(*matchType)
	}
	v.validateHTTPNameValue(obj, path, "header", name, value,
		headerType, string(policyv1b3.HeaderMatchExact), string(policyv1b3.HeaderMatchRegularExpression))
}

func (v *validator) validateHTTPNameValue(obj *Object, path, what, name, value, matchType, exactType, regexType string) {
	if name == "" {
		v.add(obj, field(path, "name"), ReasonRequired,
			fmt.Sprintf("%s match must have a name", what), SeverityError)
	}
	if value == "" {
		v.add(obj, field(path, "value"), ReasonRequired,
			fmt.Sprintf("%s match %q must have a value", what, name), SeverityError)
	}
	if name != "" && matchType != exactType && matchType != regexType {
		v.add(obj, field(path, "type"), ReasonUnsupportedValue,
			fmt.Sprintf("unsupported %s match type %q", what, matchType), SeverityError)
	}
}

func (v *validator) validateHTTPFilter(obj *Object, path, filterType string) {
	if filterType == "" {
		v.add(obj, field(path, "type"), ReasonRequired,
			"filter must have a type", SeverityError)
		return
	}
	if _, ok := supportedHTTPRouteFilterTypes[filterType]; ok {
		return
	}
	switch filterType {
	case "RequestMirror", "URLRewrite", "ExtensionRef":
		v.add(obj, field(path, "type"), ReasonUnsupportedFilter,
			fmt.Sprintf("%s filters are not supported by the Linkerd policy controller", filterType), SeverityError)
	default:
		v.add(obj, field(path, "type"), ReasonUnsupportedValue,
			fmt.Sprintf("unsupported filter type %q", filterType), SeverityError)
	}
}

// validateRawRouteTimeouts validates spec.rules[*].timeouts against the
// generic, retained document. Durations are encoded as strings and a malformed
// value prevents typed decoding entirely, so the raw walk is the only way to
// report a precise field path for them.
func (v *validator) validateRawRouteTimeouts(obj *Object) {
	spec, ok := obj.Raw["spec"].(map[string]any)
	if !ok {
		return
	}
	rules, ok := spec["rules"].([]any)
	if !ok {
		return
	}
	for i, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		rawTimeouts, ok := rule["timeouts"].(map[string]any)
		if !ok {
			continue
		}
		timeoutsPath := field(at("spec.rules", i), "timeouts")

		var request, backend time.Duration
		haveRequest, haveBackend := false, false
		if s, present := rawTimeouts["request"].(string); present {
			path := field(timeoutsPath, "request")
			d, ok := v.parseTimeout(obj, path, "request", s)
			request, haveRequest = d, ok
		}
		if s, present := rawTimeouts["backendRequest"].(string); present {
			path := field(timeoutsPath, "backendRequest")
			d, ok := v.parseTimeout(obj, path, "backendRequest", s)
			backend, haveBackend = d, ok
		}
		if haveRequest && haveBackend && request > 0 && backend > request {
			v.add(obj, field(timeoutsPath, "backendRequest"), ReasonTimeoutExceedsRequest,
				fmt.Sprintf("backendRequest timeout (%s) must be <= request timeout (%s)", backend, request), SeverityError)
		}
	}
}

func (v *validator) parseTimeout(obj *Object, path, name, value string) (time.Duration, bool) {
	d, err := time.ParseDuration(value)
	if err != nil {
		v.add(obj, path, ReasonInvalidDuration,
			fmt.Sprintf("invalid %s timeout %q: %s", name, value, err), SeverityError)
		return 0, false
	}
	if d < 0 {
		v.add(obj, path, ReasonNegativeDuration,
			fmt.Sprintf("%s timeout must be non-negative: %q", name, value), SeverityError)
		return d, false
	}
	return d, true
}

func (v *validator) validateBackendRefs(obj *Object, path, routeNamespace string, refs []gatewayv1a2.HTTPBackendRef) {
	allWeightsZero := len(refs) > 0
	for i, ref := range refs {
		refPath := at(path, i)

		group := coreGroup
		if ref.Group != nil {
			group = string(*ref.Group)
		}
		kind := serviceKind
		if ref.Kind != nil && string(*ref.Kind) != "" {
			kind = string(*ref.Kind)
		}

		if ref.Name == "" {
			v.add(obj, field(refPath, "name"), ReasonRequired,
				"backendRef must reference a name", SeverityError)
		}

		switch {
		case kind == serviceKind && group == coreGroup:
			if ref.Port == nil {
				v.add(obj, refPath, ReasonBackendPortRequired,
					fmt.Sprintf("port is required when the referent is a Kubernetes Service (%q)", ref.Name), SeverityError)
			} else if *ref.Port < 1 || *ref.Port > 65535 {
				v.add(obj, field(refPath, "port"), ReasonInvalidPort,
					fmt.Sprintf("backendRef port must be between 1 and 65535: %d", *ref.Port), SeverityError)
			}
		case kind == egressKind && group == policyGroup:
			// EgressNetwork backends are a Linkerd extension and do not
			// require a port.
		default:
			v.add(obj, field(refPath, "kind"), ReasonUnsupportedBackend,
				fmt.Sprintf("unsupported backend type %s/%s; the policy controller produces an invalid backend for unknown kinds", group, kind), SeverityError)
		}

		weight := int32(1)
		if ref.Weight != nil {
			weight = *ref.Weight
			if weight < 0 {
				v.add(obj, field(refPath, "weight"), ReasonInvalidWeight,
					fmt.Sprintf("backendRef weight must not be negative: %d", weight), SeverityError)
			}
			if weight > 1000000 {
				v.add(obj, field(refPath, "weight"), ReasonInvalidWeight,
					fmt.Sprintf("backendRef weight must not exceed 1000000: %d", weight), SeverityError)
			}
		}
		if weight != 0 {
			allWeightsZero = false
		}

		namespace := routeNamespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}
		if ref.Namespace != nil && namespace != routeNamespace && ref.Name != "" {
			if !v.referenceAllowed(
				obj.Ref.Group, httpRouteKind, routeNamespace,
				namespace, group, kind, string(ref.Name),
			) {
				v.add(obj, field(refPath, "namespace"), ReasonBackendCrossNamespace,
					fmt.Sprintf("backendRef to %s/%s %q in namespace %q requires a ReferenceGrant in namespace %q allowing HTTPRoute %q from namespace %q",
						group, kind, ref.Name, namespace, namespace, obj.Ref.Name, routeNamespace), SeverityError)
			}
		}

		filtersPath := field(refPath, "filters")
		for j, filter := range ref.Filters {
			v.validateHTTPFilter(obj, at(filtersPath, j), string(filter.Type))
		}
	}
	if allWeightsZero {
		v.add(obj, path, ReasonInvalidWeight,
			"all backendRefs have weight 0; requests matching this rule receive an HTTP 500 response", SeverityWarning)
	}
}

// referenceAllowed reports whether a ReferenceGrant retained in the snapshot
// permits a reference from the given route to the given backend.
func (v *validator) referenceAllowed(fromGroup, fromKind, fromNamespace, toNamespace, toGroup, toKind, toName string) bool {
	for _, obj := range v.snapshot.referenceGrants {
		grant := obj.Grant
		// A grant governs references into its own namespace. When the
		// document omits metadata.namespace the grant is trusted to have been
		// provided in the right namespace.
		if grant.Namespace != "" && grant.Namespace != toNamespace {
			continue
		}
		fromOK, toOK := false, false
		for _, from := range grant.Spec.From {
			if string(from.Namespace) != fromNamespace || string(from.Group) != fromGroup {
				continue
			}
			if string(from.Kind) == fromKind || string(from.Kind) == "*" {
				fromOK = true
			}
		}
		for _, to := range grant.Spec.To {
			if string(to.Group) != toGroup || string(to.Kind) != toKind {
				continue
			}
			if to.Name == nil || string(*to.Name) == "" || string(*to.Name) == toName {
				toOK = true
			}
		}
		if fromOK && toOK {
			return true
		}
	}
	return false
}

// mergeContribution is a single match predicate contributed to a Service by an
// HTTPRoute rule during policy-controller-style merging.
type mergeContribution struct {
	obj       *Object
	matchPath string
	signature string
	createdAt time.Time
	routeKey  string
	ruleIdx   int
	matchIdx  int
	origin    string
}

// mergeTargetKey identifies one merge group: the targeted Service plus the
// namespace from which the route contributes (consumer routes are scoped to
// the route's own namespace).
type mergeTargetKey struct {
	group, kind, namespace, name, section string
	port                                  int32
	routeNamespace                        string
}

func (k mergeTargetKey) String() string {
	return strings.Join([]string{
		k.routeNamespace, k.group, k.kind, k.namespace, k.name,
		k.section, fmt.Sprint(k.port),
	}, "\x00")
}

// validateHTTPRouteMerge replicates the additive merge the policy controller
// performs for HTTPRoutes attached to the same Service: rules are concatenated
// and equal match predicates from distinct (or later) contributions lose
// precedence, following Gateway API tie-breaking (creation timestamp, then
// namespace/name, then rule order).
func (v *validator) validateHTTPRouteMerge() {
	contributions := map[mergeTargetKey][]mergeContribution{}
	for _, obj := range v.snapshot.httpRoutes {
		route := obj.Route
		for _, ref := range route.Spec.ParentRefs {
			parent := normalizeParentRef(ref, route.Namespace)
			if parent.kind != serviceKind || parent.group != coreGroup || parent.name == "" {
				continue
			}
			key := mergeTargetKey{
				group: parent.group, kind: parent.kind, namespace: parent.namespace,
				name: parent.name, section: parent.section, port: parent.port,
				routeNamespace: route.Namespace,
			}
			for ruleIdx, rule := range route.Spec.Rules {
				if len(rule.Matches) == 0 {
					// An absent match defaults to prefix "/".
					contributions[key] = append(contributions[key], v.newContribution(obj, ruleIdx, -1, nil))
					continue
				}
				for matchIdx := range rule.Matches {
					match := rule.Matches[matchIdx]
					contributions[key] = append(contributions[key], v.newContribution(obj, ruleIdx, matchIdx, &match))
				}
			}
		}
	}

	targets := make([]mergeTargetKey, 0, len(contributions))
	for key := range contributions {
		targets = append(targets, key)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].String() < targets[j].String()
	})

	for _, key := range targets {
		merged := contributions[key]
		sort.SliceStable(merged, func(i, j int) bool {
			if !merged[i].createdAt.Equal(merged[j].createdAt) {
				return merged[i].createdAt.Before(merged[j].createdAt)
			}
			if merged[i].routeKey != merged[j].routeKey {
				return merged[i].routeKey < merged[j].routeKey
			}
			if merged[i].ruleIdx != merged[j].ruleIdx {
				return merged[i].ruleIdx < merged[j].ruleIdx
			}
			return merged[i].matchIdx < merged[j].matchIdx
		})

		winners := map[string]mergeContribution{}
		for _, contribution := range merged {
			winner, exists := winners[contribution.signature]
			if exists {
				v.add(contribution.obj, contribution.matchPath, ReasonConflictingRouteMatch,
					fmt.Sprintf("match is also contributed by %s attached to Service %s/%s; the older route wins attachment precedence and this match is ignored",
						winner.origin, key.namespace, key.name), SeverityWarning)
				continue
			}
			winners[contribution.signature] = contribution
		}
	}
}

func (v *validator) newContribution(obj *Object, ruleIdx, matchIdx int, match *policyv1b3.HTTPRouteMatch) mergeContribution {
	matchPath := at("spec.rules", ruleIdx)
	if matchIdx >= 0 {
		matchPath = at(field(matchPath, "matches"), matchIdx)
	}
	return mergeContribution{
		obj:       obj,
		matchPath: matchPath,
		signature: matchSignature(match),
		createdAt: obj.Route.CreationTimestamp.Time,
		routeKey:  obj.Route.Namespace + "/" + obj.Route.Name,
		ruleIdx:   ruleIdx,
		matchIdx:  matchIdx,
		origin:    fmt.Sprintf("HTTPRoute %s/%s %s", obj.Route.Namespace, obj.Route.Name, matchPath),
	}
}

// matchSignature renders a stable canonical representation of a match
// predicate, applying the Gateway API defaults (prefix "/" path).
func matchSignature(match *policyv1b3.HTTPRouteMatch) string {
	var b strings.Builder
	b.WriteString("path=")
	pathType := string(policyv1b3.PathMatchPathPrefix)
	pathValue := "/"
	if match != nil && match.Path != nil {
		if match.Path.Type != nil {
			pathType = string(*match.Path.Type)
		}
		if match.Path.Value != nil {
			pathValue = *match.Path.Value
		}
	}
	b.WriteString(pathType)
	b.WriteString(":")
	b.WriteString(pathValue)

	if match != nil {
		if match.Method != nil {
			b.WriteString("|method=")
			b.WriteString(string(*match.Method))
		}
		writeHeaderSignatures(&b, "header", match.Headers)
		writeQuerySignatures(&b, "query", match.QueryParams)
	}
	return b.String()
}

func writeHeaderSignatures(b *strings.Builder, label string, headers []policyv1b3.HTTPHeaderMatch) {
	parts := make([]string, 0, len(headers))
	for _, header := range headers {
		t := policyv1b3.HeaderMatchExact
		if header.Type != nil {
			t = *header.Type
		}
		parts = append(parts, string(header.Name)+"="+string(t)+":"+header.Value)
	}
	sort.Strings(parts)
	for _, p := range parts {
		b.WriteString("|")
		b.WriteString(label)
		b.WriteString("=")
		b.WriteString(p)
	}
}

func writeQuerySignatures(b *strings.Builder, label string, queries []policyv1b3.HTTPQueryParamMatch) {
	parts := make([]string, 0, len(queries))
	for _, query := range queries {
		t := policyv1b3.QueryParamMatchExact
		if query.Type != nil {
			t = *query.Type
		}
		parts = append(parts, query.Name+"="+string(t)+":"+query.Value)
	}
	sort.Strings(parts)
	for _, p := range parts {
		b.WriteString("|")
		b.WriteString(label)
		b.WriteString("=")
		b.WriteString(p)
	}
}
