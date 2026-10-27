use super::validation;
use crate::k8s::policy::{
    httproute, AuthorizationPolicy, AuthorizationPolicySpec, EgressNetwork, EgressNetworkSpec,
    HttpLocalRateLimitPolicy, HttpRoute, HttpRouteSpec, MeshTLSAuthentication,
    MeshTLSAuthenticationSpec, NamespacedTargetRef, Network, NetworkAuthentication,
    NetworkAuthenticationSpec, RateLimitPolicySpec, Server, ServerAuthorization,
    ServerAuthorizationSpec, ServerSpec,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use futures::future;
use http_body_util::BodyExt;
use hyper::{http, Request, Response};
use k8s_openapi::api::core::v1::{Namespace, ServiceAccount};
use kube::{core::DynamicObject, Resource, ResourceExt};
use linkerd_policy_controller_k8s_api::gateway;
use linkerd_policy_controller_k8s_index::{self as index, outbound::index as outbound_index};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

#[derive(Clone)]
pub struct Admission {
    /// The live inbound policy index, used for read-only dry-run authorization
    /// evaluations. Dry-runs only read the index; Kubernetes objects are never
    /// created or modified.
    index: index::inbound::SharedIndex,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read request body: {0}")]
    Request(#[from] hyper::Error),

    #[error("failed to encode json response: {0}")]
    Json(#[from] serde_json::Error),
}

type Review = kube::core::admission::AdmissionReview<DynamicObject>;
type AdmissionRequest = kube::core::admission::AdmissionRequest<DynamicObject>;
type AdmissionResponse = kube::core::admission::AdmissionResponse;
type AdmissionReview = kube::core::admission::AdmissionReview<DynamicObject>;

#[async_trait::async_trait]
trait Validate<T> {
    // If true, parse failures are admitted with a warning instead of denied.
    // Used for Gateway API types, where interoperability with other controllers
    // takes precedence over strict schema enforcement.
    fn lenient() -> bool {
        false
    }

    async fn validate(
        self,
        ns: &str,
        name: &str,
        annotations: &BTreeMap<String, String>,
        spec: T,
    ) -> Result<()>;
}

type Body = http_body_util::Full<bytes::Bytes>;

// === impl AdmissionService ===

impl tower::Service<Request<hyper::body::Incoming>> for Admission {
    type Response = Response<Body>;
    type Error = Error;
    type Future = future::BoxFuture<'static, Result<Response<Body>, Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<hyper::body::Incoming>) -> Self::Future {
        trace!(?req);
        if req.method() != http::Method::POST {
            return Box::pin(future::ok(
                Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Body::default())
                    .expect("not found response must be valid"),
            ));
        }

        let path = req.uri().path().to_string();
        let admission = self.clone();
        Box::pin(async move {
            // The dry-run authorization API. Unlike admission reviews, this
            // evaluates an explicit (namespace, pod, port, client) tuple
            // against the live index without involving the Kubernetes API.
            if path == "/dryrun" {
                return admission.dry_run_http(req).await;
            }

            if path != "/" {
                return Ok(Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Body::default())
                    .expect("not found response must be valid"));
            }

            use bytes::Buf;
            let bytes = req.into_body().collect().await?.to_bytes();
            let review: Review = match serde_json::from_reader(bytes.reader()) {
                Ok(review) => review,
                Err(error) => {
                    warn!(%error, "Failed to parse request body");
                    return json_response(AdmissionResponse::invalid(error).into_review());
                }
            };
            trace!(?review);

            let rsp = match review.try_into() {
                Ok(req) => {
                    debug!(?req);
                    admission.admit(req).await
                }
                Err(error) => {
                    warn!(%error, "Invalid admission request");
                    AdmissionResponse::invalid(error)
                }
            };
            debug!(?rsp);
            json_response(rsp.into_review())
        })
    }
}

impl Admission {
    pub fn new(index: index::inbound::SharedIndex) -> Self {
        Self { index }
    }

    /// Handles `POST /dryrun`: a JSON [`index::inbound::DryRunRequest`] is
    /// evaluated against a single consistent index snapshot and answered with
    /// a JSON [`index::inbound::DryRunResponse`]. Nothing is persisted to the
    /// Kubernetes API.
    async fn dry_run_http(
        self,
        req: Request<hyper::body::Incoming>,
    ) -> std::result::Result<Response<Body>, Error> {
        use bytes::Buf;
        let bytes = req.into_body().collect().await?.to_bytes();
        let request: index::inbound::DryRunRequest = match serde_json::from_reader(bytes.reader()) {
            Ok(request) => request,
            Err(error) => {
                warn!(%error, "Failed to parse dry-run request");
                return json_error_response(http::StatusCode::BAD_REQUEST, &error.to_string());
            }
        };

        // Holding the read guard for the whole evaluation ensures that the
        // response's resourceVersion cannot mix with a concurrent policy
        // update.
        match self.index.read().dry_run(request) {
            Ok(response) => {
                let body = serde_json::to_vec(&response)?;
                Ok(Response::builder()
                    .status(http::StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("dry-run response must be valid"))
            }
            Err(error) => {
                let status = if error.is_not_found() {
                    http::StatusCode::NOT_FOUND
                } else {
                    http::StatusCode::BAD_REQUEST
                };
                json_error_response(status, &error.to_string())
            }
        }
    }

    async fn admit(self, req: AdmissionRequest) -> AdmissionResponse {
        if is_kind::<AuthorizationPolicy>(&req) {
            return self.admit_spec::<AuthorizationPolicySpec>(req).await;
        }

        if is_kind::<MeshTLSAuthentication>(&req) {
            return self.admit_spec::<MeshTLSAuthenticationSpec>(req).await;
        }

        if is_kind::<NetworkAuthentication>(&req) {
            return self.admit_spec::<NetworkAuthenticationSpec>(req).await;
        }

        if is_kind::<Server>(&req) {
            return self.admit_spec::<ServerSpec>(req).await;
        };

        if is_kind::<ServerAuthorization>(&req) {
            // Server-side dry-run admission requests are admitted without
            // writing anything, but annotated with an overlay evaluation of the
            // candidate ServerAuthorization against the live index.
            if req.dry_run {
                return self.admit_server_authorization_dry_run(req).await;
            }
            return self.admit_spec::<ServerAuthorizationSpec>(req).await;
        };

        if is_kind::<HttpRoute>(&req) {
            return self.admit_spec::<HttpRouteSpec>(req).await;
        }

        if is_kind::<EgressNetwork>(&req) {
            return self.admit_spec::<EgressNetworkSpec>(req).await;
        }

        if is_kind::<gateway::HTTPRoute>(&req) {
            return self.admit_spec::<gateway::HttpRouteSpec>(req).await;
        }

        if is_kind::<gateway::GRPCRoute>(&req) {
            return self.admit_spec::<gateway::GrpcRouteSpec>(req).await;
        }

        if is_kind::<gateway::TLSRoute>(&req) {
            // TLSRoute is served under several versions, which differ in that
            // `v1` requires `spec.hostnames` and `v1alpha2` does not.
            if req.kind.version == gateway::TlsRouteApiVersion::V1Alpha2.version() {
                return self.admit_spec::<gateway::TlsRouteSpecV1Alpha2>(req).await;
            }
            return self.admit_spec::<gateway::TlsRouteSpec>(req).await;
        }

        if is_kind::<gateway::TCPRoute>(&req) {
            return self.admit_spec::<gateway::TcpRouteSpec>(req).await;
        }

        if is_kind::<HttpLocalRateLimitPolicy>(&req) {
            return self.admit_spec::<RateLimitPolicySpec>(req).await;
        }

        AdmissionResponse::invalid(format_args!(
            "unsupported resource type: {}.{}.{}",
            req.kind.group, req.kind.version, req.kind.kind
        ))
    }

    async fn admit_spec<T>(self, req: AdmissionRequest) -> AdmissionResponse
    where
        T: DeserializeOwned,
        Self: Validate<T>,
    {
        let rsp = AdmissionResponse::from(&req);

        let kind = req.kind.kind.clone();
        let (obj, spec) = match parse_spec::<T>(req) {
            Ok(spec) => spec,
            Err(error) => {
                if <Self as Validate<T>>::lenient() {
                    warn!(%error, "Failed to parse {} spec; admitting anyway", kind);
                    return rsp;
                }
                info!(%error, "Failed to parse {} spec", kind);
                return rsp.deny(error);
            }
        };

        let ns = obj.namespace().unwrap_or_default();
        let name = obj.name_any();
        let annotations = obj.annotations();

        if let Err(error) = self.validate(&ns, &name, annotations, spec).await {
            info!(%error, %ns, %name, %kind, "Denied");
            return rsp.deny(error);
        }

        rsp
    }

    /// Validates a server-side dry-run `ServerAuthorization` request and, when
    /// the spec is valid, overlays the candidate resource onto the live index
    /// to report which servers it would select and which identities it would
    /// require. The candidate is never written to Kubernetes.
    async fn admit_server_authorization_dry_run(self, req: AdmissionRequest) -> AdmissionResponse {
        let rsp = AdmissionResponse::from(&req);

        let (obj, spec) = match parse_spec::<ServerAuthorizationSpec>(req) {
            Ok(parsed) => parsed,
            Err(error) => {
                info!(%error, "Failed to parse ServerAuthorization spec");
                return rsp.deny(error);
            }
        };

        let ns = obj.namespace().unwrap_or_default();
        let name = obj.name_any();
        let annotations = obj.annotations();
        // `validate` takes `self` by value, so validate a clone and keep the
        // index handle for the overlay evaluation below.
        if let Err(error) = self.clone().validate(&ns, &name, annotations, spec).await {
            info!(%error, %ns, %name, "Denied dry-run ServerAuthorization");
            return rsp.deny(error);
        }

        // Re-deserialize the dynamic object into a typed
        // ServerAuthorization so it can be overlaid on the index.
        let candidate = match serde_json::to_value(&obj)
            .and_then(serde_json::from_value::<ServerAuthorization>)
        {
            Ok(candidate) => candidate,
            Err(error) => {
                warn!(%error, "Failed to read dry-run ServerAuthorization object");
                return rsp.deny(anyhow!("failed to read ServerAuthorization: {error}"));
            }
        };

        match self.index.read().preview_server_authorization(candidate) {
            Ok(preview) => {
                let mut rsp = rsp;
                rsp.warnings = Some(preview_warnings(&preview));
                rsp
            }
            Err(error) => {
                info!(%error, %ns, %name, "Dry-run ServerAuthorization evaluation failed");
                rsp.deny(anyhow!("dry-run evaluation failed: {error}"))
            }
        }
    }
}

fn is_kind<T>(req: &AdmissionRequest) -> bool
where
    T: Resource,
    T::DynamicType: Default,
{
    let dt = Default::default();
    req.kind.group.eq_ignore_ascii_case(&T::group(&dt))
        && req.kind.kind.eq_ignore_ascii_case(&T::kind(&dt))
}

fn json_response(rsp: AdmissionReview) -> Result<Response<Body>, Error> {
    let bytes = serde_json::to_vec(&rsp)?;
    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .expect("admission review response must be valid"))
}

fn json_error_response(
    status: http::StatusCode,
    message: &str,
) -> std::result::Result<Response<Body>, Error> {
    let bytes = serde_json::to_vec(&serde_json::json!({ "error": message }))?;
    Ok(Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .expect("error response must be valid"))
}

/// Kubernetes truncates admission warnings beyond this length, so keep each
/// warning within it.
const WARNING_MAX_LEN: usize = 256;

/// Formats the dry-run preview of a candidate `ServerAuthorization` as
/// admission warnings describing the servers it would select and the identity
/// requirements it would impose. No object is persisted.
fn preview_warnings(preview: &index::inbound::ServerAuthorizationPreview) -> Vec<String> {
    fn truncate(message: String) -> String {
        if message.len() <= WARNING_MAX_LEN {
            return message;
        }
        let mut truncated = message;
        truncated.truncate(WARNING_MAX_LEN - 3);
        truncated.push_str("...");
        truncated
    }

    let mut warnings = Vec::new();

    if preview.selected_servers.is_empty() {
        warnings.push(truncate(format!(
            "dry-run: ServerAuthorization \"{}\" selects no live Server in namespace \"{}\" at \
             index resourceVersion {}; existing policies for the affected ports are unchanged",
            preview.name, preview.namespace, preview.resource_version,
        )));
    } else {
        let names = preview
            .selected_servers
            .iter()
            .map(|server| server.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        warnings.push(truncate(format!(
            "dry-run: ServerAuthorization \"{}\" would select {} Server(s) [{names}] at index \
             resourceVersion {}",
            preview.name,
            preview.selected_servers.len(),
            preview.resource_version,
        )));
    }

    let networks = if preview.networks.is_empty() {
        "the cluster networks".to_string()
    } else {
        preview.networks.join(", ")
    };
    match preview.authentication.as_str() {
        "meshtls" => warnings.push(truncate(format!(
            "dry-run: requires mesh identity: {} (source networks: {networks})",
            preview.identities.join(", ")
        ))),
        "unauthenticated-tls" => warnings.push(truncate(format!(
            "dry-run: requires mesh TLS without a workload identity (ingress mode) from \
             {networks}"
        ))),
        _ => warnings.push(truncate(format!(
            "dry-run: permits unauthenticated clients from {networks}"
        ))),
    }

    warnings
}

fn parse_spec<T: DeserializeOwned>(req: AdmissionRequest) -> Result<(DynamicObject, T)> {
    let obj = req
        .object
        .ok_or_else(|| anyhow!("admission request missing 'object"))?;

    let spec = {
        let data = obj
            .data
            .get("spec")
            .cloned()
            .ok_or_else(|| anyhow!("admission request missing 'spec'"))?;
        serde_json::from_value(data)?
    };

    Ok((obj, spec))
}

#[async_trait::async_trait]
impl Validate<AuthorizationPolicySpec> for Admission {
    async fn validate(
        self,
        ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: AuthorizationPolicySpec,
    ) -> Result<()> {
        if spec.target_ref.targets_kind::<Namespace>() && spec.target_ref.name != ns {
            bail!("cannot target another namespace: {}", &spec.target_ref.name);
        }

        let mtls_authns_count = spec
            .required_authentication_refs
            .iter()
            .filter(|authn| authn.targets_kind::<MeshTLSAuthentication>())
            .count();
        if mtls_authns_count > 1 {
            bail!("only a single MeshTLSAuthentication may be set");
        }

        let sa_authns_count = spec
            .required_authentication_refs
            .iter()
            .filter(|authn| authn.targets_kind::<ServiceAccount>())
            .count();
        if sa_authns_count > 1 {
            bail!("only a single ServiceAccount may be set");
        }

        if mtls_authns_count + sa_authns_count > 1 {
            bail!("a MeshTLSAuthentication and ServiceAccount may not be set together");
        }

        let net_authns_count = spec
            .required_authentication_refs
            .iter()
            .filter(|authn| authn.targets_kind::<NetworkAuthentication>())
            .count();
        if net_authns_count > 1 {
            bail!("only a single NetworkAuthentication may be set");
        }

        if mtls_authns_count + sa_authns_count + net_authns_count
            < spec.required_authentication_refs.len()
        {
            let kinds = spec
                .required_authentication_refs
                .iter()
                .filter(|authn| {
                    !authn.targets_kind::<MeshTLSAuthentication>()
                        && !authn.targets_kind::<NetworkAuthentication>()
                        && !authn.targets_kind::<ServiceAccount>()
                })
                .map(|authn| authn.canonical_kind())
                .collect::<Vec<_>>();
            bail!("unsupported authentication kind(s): {}", kinds.join(", "));
        }

        // Confirm that the index will be able to read this spec.
        index::authorization_policy::validate(spec)?;

        Ok(())
    }
}

fn validate_identity_ref(id: &NamespacedTargetRef) -> Result<()> {
    if id.targets_kind::<ServiceAccount>() {
        return Ok(());
    }

    if id.targets_kind::<Namespace>() {
        if id.namespace.is_some() {
            bail!("Namespace identity_ref is cluster-scoped and cannot have a namespace");
        }
        return Ok(());
    }

    bail!("invalid identity target kind: {}", id.canonical_kind());
}

#[async_trait::async_trait]
impl Validate<MeshTLSAuthenticationSpec> for Admission {
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: MeshTLSAuthenticationSpec,
    ) -> Result<()> {
        for id in spec.identities.iter().flatten() {
            if let Err(err) = validation::validate_identity(id) {
                bail!("id {id} is invalid: {err}");
            }
        }

        for id in spec.identity_refs.iter().flatten() {
            validate_identity_ref(id)?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Validate<ServerSpec> for Admission {
    /// Checks that `spec` has an `accessPolicy` with a valid value.
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: ServerSpec,
    ) -> Result<()> {
        if let Some(policy) = spec.access_policy {
            policy
                .parse::<index::DefaultPolicy>()
                .map_err(|err| anyhow!("Invalid 'accessPolicy' field: {err}"))?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Validate<NetworkAuthenticationSpec> for Admission {
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: NetworkAuthenticationSpec,
    ) -> Result<()> {
        if spec.networks.is_empty() {
            bail!("at least one network must be specified");
        }

        validate_networks(spec.networks)
    }
}

#[async_trait::async_trait]
impl Validate<EgressNetworkSpec> for Admission {
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: EgressNetworkSpec,
    ) -> Result<()> {
        if let Some(networks) = spec.networks {
            if networks.is_empty() {
                bail!("at least one network must be specified");
            }

            return validate_networks(networks);
        }

        Ok(())
    }
}

fn validate_networks(networks: Vec<Network>) -> Result<()> {
    for net in networks.into_iter() {
        for except in net.except.into_iter().flatten() {
            if except.contains(&net.cidr) {
                bail!(
                    "cidr '{}' is completely negated by exception '{}'",
                    net.cidr,
                    except
                );
            }
            if !net.cidr.contains(&except) {
                bail!(
                    "cidr '{}' does not include exception '{}'",
                    net.cidr,
                    except
                );
            }
        }
    }

    Ok(())
}

#[async_trait::async_trait]
impl Validate<ServerAuthorizationSpec> for Admission {
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: ServerAuthorizationSpec,
    ) -> Result<()> {
        if let Some(mtls) = spec.client.mesh_tls.as_ref() {
            if spec.client.unauthenticated {
                bail!("`unauthenticated` must be false if `mesh_tls` is specified");
            }
            if mtls.unauthenticated_tls {
                let ids = mtls.identities.as_ref().map(|ids| ids.len()).unwrap_or(0);
                let sas = mtls
                    .service_accounts
                    .as_ref()
                    .map(|sas| sas.len())
                    .unwrap_or(0);
                if ids + sas > 0 {
                    bail!("`unauthenticatedTLS` be false if any `identities` or `service_accounts` is specified");
                }
            }
        }

        for net in spec.client.networks.into_iter().flatten() {
            for except in net.except.into_iter().flatten() {
                if except.contains(&net.cidr) {
                    bail!(
                        "cidr '{}' is completely negated by exception '{}'",
                        net.cidr,
                        except
                    );
                }
                if !net.cidr.contains(&except) {
                    bail!(
                        "cidr '{}' does not include exception '{}'",
                        net.cidr,
                        except
                    );
                }
            }
        }

        Ok(())
    }
}

fn validate_match(httproute_rules_match: gateway::HttpRouteRulesMatches) -> Result<()> {
    index::routes::http::try_match(httproute_rules_match).map(|_| ())
}

#[async_trait::async_trait]
impl Validate<HttpRouteSpec> for Admission {
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        annotations: &BTreeMap<String, String>,
        spec: HttpRouteSpec,
    ) -> Result<()> {
        for parent in spec.parent_refs.iter().flatten() {
            if outbound_index::is_parent_egress_network(&parent.kind, &parent.group)
                && parent.port.is_none()
            {
                bail!("cannot target an EgressNetwork without specifying a port");
            }
        }

        // Validate retry and timeout annotations on the Route itself. The
        // admission webhook does not intercept core/v1 Services, so annotations
        // set directly on a Service are checked later, at indexer time.
        if spec.parent_refs.iter().flatten().any(|parent| {
            outbound_index::is_parent_service_or_egress_network(&parent.kind, &parent.group)
        }) {
            outbound_index::http::parse_http_retry(annotations)?;
            outbound_index::parse_timeouts(annotations)?;
        }

        fn validate_filter(filter: httproute::HttpRouteFilter) -> Result<()> {
            match filter {
                httproute::HttpRouteFilter::RequestHeaderModifier {
                    request_header_modifier,
                } => index::routes::http::request_header_modifier(request_header_modifier)
                    .map(|_| ()),
                httproute::HttpRouteFilter::ResponseHeaderModifier {
                    response_header_modifier,
                } => index::routes::http::response_header_modifier(response_header_modifier)
                    .map(|_| ()),
                httproute::HttpRouteFilter::RequestRedirect { request_redirect } => {
                    index::routes::http::req_redirect(request_redirect).map(|_| ())
                }
            }
        }

        fn validate_timeouts(timeouts: httproute::HttpRouteTimeouts) -> Result<()> {
            use std::time::Duration;

            if let Some(t) = timeouts.backend_request {
                ensure!(
                    !t.is_negative(),
                    "backendRequest timeout must not be negative"
                );
            }

            if let Some(t) = timeouts.request {
                ensure!(!t.is_negative(), "request timeout must not be negative");
            }

            if let (Some(req), Some(backend_req)) = (timeouts.request, timeouts.backend_request) {
                ensure!(
                    Duration::from(req) >= Duration::from(backend_req),
                    "backendRequest timeout ({backend_req}) must not be greater than request timeout ({req})"
                );
            }
            Ok(())
        }

        // Validate the rules in this spec.
        // This is essentially equivalent to the indexer's conversion function
        // from `HttpRouteSpec` to `InboundRouteBinding`, except that we don't
        // actually allocate stuff in order to return an `InboundRouteBinding`.
        for httproute::HttpRouteRule {
            filters,
            matches,
            timeouts,
            ..
        } in spec.rules.into_iter().flatten()
        {
            for m in matches.into_iter().flatten() {
                validate_match(m)?;
            }

            for f in filters.into_iter().flatten() {
                validate_filter(f)?;
            }

            if let Some(timeouts) = timeouts {
                validate_timeouts(timeouts)?;
            }
        }

        Ok(())
    }
}

fn validate_http_backend_if_service(br: &gateway::HttpRouteRulesBackendRefs) -> Result<()> {
    let is_service = matches!(br.group.as_deref(), Some("core") | Some("") | None)
        && matches!(br.kind.as_deref(), Some("Service") | None);

    // If the backend reference is a Service, it must have a port. If it is not
    // a Service, then we have to admit it for interoperability with other
    // controllers.
    if is_service && matches!(br.port, None | Some(0)) {
        bail!("cannot reference a Service without a port");
    }

    Ok(())
}

fn validate_grpc_backend_if_service(br: &gateway::GrpcRouteRulesBackendRefs) -> Result<()> {
    let is_service = matches!(br.group.as_deref(), Some("core") | Some("") | None)
        && matches!(br.kind.as_deref(), Some("Service") | None);

    // If the backend reference is a Service, it must have a port. If it is not
    // a Service, then we have to admit it for interoperability with other
    // controllers.
    if is_service && matches!(br.port, None | Some(0)) {
        bail!("cannot reference a Service without a port");
    }

    Ok(())
}

#[async_trait::async_trait]
impl Validate<gateway::HttpRouteSpec> for Admission {
    fn lenient() -> bool {
        true
    }

    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        annotations: &BTreeMap<String, String>,
        spec: gateway::HttpRouteSpec,
    ) -> Result<()> {
        for parent in spec.parent_refs.iter().flatten() {
            if outbound_index::is_parent_egress_network(&parent.kind, &parent.group)
                && parent.port.is_none()
            {
                bail!("cannot target an EgressNetwork without specifying a port");
            }
        }

        // See the note in Validate<HttpRouteSpec>. This route type is
        // validated the same way.
        if spec.parent_refs.iter().flatten().any(|parent| {
            outbound_index::is_parent_service_or_egress_network(&parent.kind, &parent.group)
        }) {
            outbound_index::http::parse_http_retry(annotations)?;
            outbound_index::parse_timeouts(annotations)?;
        }

        fn validate_filter(filter: gateway::HttpRouteRulesFilters) -> Result<()> {
            if let Some(request_header_modifier) = filter.request_header_modifier {
                index::routes::http::request_header_modifier(request_header_modifier)?;
            }
            if let Some(response_header_modifier) = filter.response_header_modifier {
                index::routes::http::response_header_modifier(response_header_modifier)?;
            }
            if let Some(request_redirect) = filter.request_redirect {
                index::routes::http::req_redirect(request_redirect)?;
            }
            Ok(())
        }

        // Validate the rules in this spec.
        // This is essentially equivalent to the indexer's conversion function
        // from `HttpRouteSpec` to `InboundRouteBinding`, except that we don't
        // actually allocate stuff in order to return an `InboundRouteBinding`.
        for gateway::HttpRouteRules {
            filters,
            matches,
            backend_refs,
            ..
        } in spec.rules.into_iter().flatten()
        {
            for m in matches.into_iter().flatten() {
                validate_match(m)?;
            }

            for f in filters.into_iter().flatten() {
                validate_filter(f)?;
            }

            for br in backend_refs.iter().flatten() {
                validate_http_backend_if_service(br).context("invalid backendRef")?;
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Validate<gateway::GrpcRouteSpec> for Admission {
    fn lenient() -> bool {
        true
    }

    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        annotations: &BTreeMap<String, String>,
        spec: gateway::GrpcRouteSpec,
    ) -> Result<()> {
        for parent in spec.parent_refs.iter().flatten() {
            if outbound_index::is_parent_egress_network(&parent.kind, &parent.group)
                && parent.port.is_none()
            {
                bail!("cannot target an EgressNetwork without specifying a port");
            }
        }

        // See the note in Validate<HttpRouteSpec>. This route type is
        // validated the same way.
        if spec.parent_refs.iter().flatten().any(|parent| {
            outbound_index::is_parent_service_or_egress_network(&parent.kind, &parent.group)
        }) {
            outbound_index::grpc::parse_grpc_retry(annotations)?;
            outbound_index::parse_timeouts(annotations)?;
        }

        fn validate_filter(filter: gateway::GrpcRouteRulesFilters) -> Result<()> {
            if let Some(request_header_modifier) = filter.request_header_modifier {
                index::routes::grpc::request_header_modifier(request_header_modifier)?;
            }
            if let Some(response_header_modifier) = filter.response_header_modifier {
                index::routes::grpc::response_header_modifier(response_header_modifier)?;
            }
            Ok(())
        }

        fn validate_match_rule(matches: gateway::GrpcRouteRulesMatches) -> Result<()> {
            index::routes::grpc::try_match(matches).map(|_| ())
        }

        // Validate the rules in this spec.
        // This is essentially just a check to ensure that none
        // of the rules are improperly constructed (e.g. include
        // a `GrpcMethodMatch` rule where neither `method.method`
        // nor `method.service` actually contain a value)
        for gateway::GrpcRouteRules {
            filters,
            matches,
            backend_refs,
            ..
        } in spec.rules.into_iter().flatten()
        {
            for rule in matches.into_iter().flatten() {
                validate_match_rule(rule)?;
            }

            for filter in filters.into_iter().flatten() {
                validate_filter(filter)?;
            }

            for br in backend_refs.iter().flatten() {
                validate_grpc_backend_if_service(br).context("invalid backendRef")?;
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Validate<gateway::TlsRouteSpec> for Admission {
    fn lenient() -> bool {
        true
    }

    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: gateway::TlsRouteSpec,
    ) -> Result<()> {
        for parent in spec.parent_refs.iter().flatten() {
            if outbound_index::is_parent_egress_network(&parent.kind, &parent.group)
                && parent.port.is_none()
            {
                bail!("cannot target an EgressNetwork without specifying a port");
            }
        }

        if spec.rules.len() != 1 {
            bail!("TlsRoute supports a single rule only")
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Validate<gateway::TlsRouteSpecV1Alpha2> for Admission {
    fn lenient() -> bool {
        <Self as Validate<gateway::TlsRouteSpec>>::lenient()
    }

    async fn validate(
        self,
        ns: &str,
        name: &str,
        annotations: &BTreeMap<String, String>,
        gateway::TlsRouteSpecV1Alpha2(spec): gateway::TlsRouteSpecV1Alpha2,
    ) -> Result<()> {
        <Self as Validate<gateway::TlsRouteSpec>>::validate(self, ns, name, annotations, spec).await
    }
}

#[async_trait::async_trait]
impl Validate<gateway::TcpRouteSpec> for Admission {
    fn lenient() -> bool {
        true
    }

    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: gateway::TcpRouteSpec,
    ) -> Result<()> {
        for parent in spec.parent_refs.iter().flatten() {
            if outbound_index::is_parent_egress_network(&parent.kind, &parent.group)
                && parent.port.is_none()
            {
                bail!("cannot target an EgressNetwork without specifying a port");
            }
        }

        if spec.rules.len() != 1 {
            bail!("TcpRoute supports a single rule only")
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Validate<RateLimitPolicySpec> for Admission {
    async fn validate(
        self,
        _ns: &str,
        _name: &str,
        _annotations: &BTreeMap<String, String>,
        spec: RateLimitPolicySpec,
    ) -> Result<()> {
        if !spec.target_ref.targets_kind::<Server>() {
            bail!(
                "invalid targetRef kind: {}",
                spec.target_ref.canonical_kind()
            );
        }

        if let Some(total) = spec.total {
            if total.requests_per_second == 0 {
                bail!("total.requestsPerSecond must be greater than 0");
            }

            if let Some(ref identity) = spec.identity {
                if identity.requests_per_second > total.requests_per_second {
                    bail!("identity.requestsPerSecond must be less than or equal to total.requestsPerSecond");
                }
            }

            for ovr in spec.overrides.clone().unwrap_or_default().iter() {
                if ovr.requests_per_second > total.requests_per_second {
                    bail!("override.requestsPerSecond must be less than or equal to total.requestsPerSecond");
                }
            }
        }

        if let Some(identity) = spec.identity {
            if identity.requests_per_second == 0 {
                bail!("identity.requestsPerSecond must be greater than 0");
            }
        }

        for ovr in spec.overrides.unwrap_or_default().iter() {
            if ovr.requests_per_second == 0 {
                bail!("override.requestsPerSecond must be greater than 0");
            }

            for target_ref in ovr.client_refs.iter() {
                if !target_ref.targets_kind::<ServiceAccount>() {
                    bail!("overrides.clientRefs must target a ServiceAccount");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = "web.ns-0.serviceaccount.identity.linkerd.cluster.example.com";

    fn preview(
        authentication: &str,
        identities: Vec<String>,
        networks: Vec<String>,
        selected_servers: Vec<index::inbound::SelectedServer>,
    ) -> index::inbound::ServerAuthorizationPreview {
        index::inbound::ServerAuthorizationPreview {
            resource_version: 7,
            namespace: "ns-0".to_string(),
            name: "authz-web".to_string(),
            candidate_resource_version: None,
            authentication: authentication.to_string(),
            identities,
            networks,
            selected_servers,
        }
    }

    fn selected_server() -> index::inbound::SelectedServer {
        index::inbound::SelectedServer {
            name: "srv-8080".to_string(),
            resource_version: Some("100".to_string()),
            port: "8080".to_string(),
            protocol: "HTTP/1".to_string(),
        }
    }

    #[test]
    fn warnings_describe_matching_servers_and_required_identity() {
        let preview = preview(
            "meshtls",
            vec![IDENTITY.to_string()],
            vec!["10.0.0.0/8".to_string()],
            vec![selected_server()],
        );
        let warnings = preview_warnings(&preview);

        assert_eq!(warnings.len(), 2);
        let joined = warnings.join("\n");
        assert!(joined.contains("would select 1 Server(s) [srv-8080]"));
        assert!(joined.contains("index resourceVersion 7"));
        assert!(joined.contains(IDENTITY));
        assert!(joined.contains("10.0.0.0/8"));
        for warning in warnings {
            assert!(warning.len() <= WARNING_MAX_LEN);
        }
    }

    #[test]
    fn warnings_for_unmatched_selector_and_unauthenticated_clients() {
        let preview = preview("unauthenticated", vec![], vec![], vec![]);
        let warnings = preview_warnings(&preview);

        assert_eq!(warnings.len(), 2);
        let joined = warnings.join("\n");
        assert!(joined.contains("selects no live Server in namespace \"ns-0\""));
        assert!(joined.contains("permits unauthenticated clients from the cluster networks"));
    }

    #[test]
    fn warnings_describe_ingress_unauthenticated_tls() {
        let preview = preview(
            "unauthenticated-tls",
            vec![],
            vec!["0.0.0.0/0".to_string()],
            vec![selected_server()],
        );
        let warnings = preview_warnings(&preview);
        assert!(warnings
            .join("\n")
            .contains("requires mesh TLS without a workload identity (ingress mode)"));
    }
}
