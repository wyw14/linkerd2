//! Read-only dry-run authorization evaluation.
//!
//! A dry-run evaluates whether a hypothetical client may reach a pod port
//! against the *current* index state. It never writes to the Kubernetes API and
//! never mutates the index: it does not create per-port watches (as
//! [`super::Index::pod_server_rx`] does) nor otherwise allocate default state.
//!
//! The entire evaluation runs under the index's read lock, so every policy
//! referenced by the response is observed at a single
//! [`super::Index::revision`]. Concurrent watch events update the index
//! serially under a write lock and bump the revision, hence a response can
//! never mix policies from different revisions. Each matched policy also
//! reports the Kubernetes `metadata.resourceVersion` of the object it was
//! derived from.
//!
//! This logic connects three components:
//!
//! - the policy controller's in-memory index of live policy resources,
//! - `Server`/`ServerAuthorization`/`AuthorizationPolicy` server authorization,
//!   and
//! - the admission webhook, which exposes the evaluation over HTTP (see the
//!   `linkerd-policy-controller-runtime` crate) and annotates server-side
//!   `dryRun` admission requests with the result.

use super::super::workload;
use super::{server as server_index, Index, Namespace, Pod, PolicyIndex};
use crate::inbound::server_authorization::ServerAuthz;
use crate::{ClusterInfo, DefaultPolicy};
use linkerd_policy_controller_core::inbound::{
    AuthorizationRef, ClientAuthentication, ClientAuthorization, ProxyProtocol,
};
use linkerd_policy_controller_core::{IdentityMatch, NetworkMatch};
use linkerd_policy_controller_k8s_api::policy::server::{Port as ServerPort, Selector};
use linkerd_policy_controller_k8s_api::ResourceExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::num::NonZeroU16;

/// Describes a dry-run authorization evaluation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DryRunRequest {
    /// Namespace of the target workload.
    pub namespace: String,

    /// Name of the target pod (as indexed from the Kubernetes API).
    pub pod: String,

    /// The inbound port to evaluate.
    pub port: u16,

    /// The hypothetical client, when a concrete access decision is required.
    ///
    /// When omitted, the evaluation only reports which policies match and which
    /// identities/networks they require, without attributing allow/deny to a
    /// specific client.
    #[serde(default)]
    pub client: Option<DryRunClient>,
}

/// Describes a hypothetical client for a dry-run evaluation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DryRunClient {
    /// The client's namespace. Defaults to the target namespace when a service
    /// account is provided, mirroring namespaced policy references.
    #[serde(default)]
    pub namespace: Option<String>,

    /// The client's Kubernetes `ServiceAccount` name. Its mesh identity is
    /// derived with the cluster's trust domain.
    #[serde(default)]
    pub service_account: Option<String>,

    /// The client source IP, used to evaluate `client.networks` restrictions.
    #[serde(default)]
    pub ip: Option<IpAddr>,

    /// Indicates that the client is a cluster ingress controller (e.g. an
    /// nginx/Contour ingress terminating external traffic). Such clients are
    /// admitted by `unauthenticatedTLS` ServerAuthorizations.
    #[serde(default)]
    pub ingress: bool,
}

/// The authorization decision produced by a dry-run evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DryRunDecision {
    /// At least one authorization admits the client (or admits some client
    /// when no concrete client was described).
    Allow,
    /// No authorization admits the client; the default policy denies.
    Deny,
    /// Traffic is admitted only by the auditing default policy; it is allowed
    /// but must be audited.
    Audit,
}

/// The server (named `Server` resource or the default policy) in effect for the
/// evaluated port.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MatchedServer {
    /// `"Server"` for a named policy.linkerd.io Server, or `"Default"` when no
    /// Server selects the port.
    pub kind: String,

    /// The Server name, or the effective default policy mode
    /// (`"deny"`, `"all-authenticated"`, ...) for a default server.
    pub name: String,

    /// The Kubernetes `metadata.resourceVersion` of the matched Server, if any.
    pub resource_version: Option<String>,

    /// The configured proxy protocol.
    pub protocol: String,

    /// The evaluated port.
    pub port: u16,
}

/// An authorization matched for the evaluated port.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MatchedAuthorization {
    /// `"ServerAuthorization"`, `"AuthorizationPolicy"` or `"default"`.
    pub kind: String,

    /// The resource name (or the default policy mode for `default` refs).
    pub name: String,

    /// The Kubernetes `metadata.resourceVersion` of the policy resource.
    pub resource_version: Option<String>,

    /// How clients must authenticate: `"unauthenticated"`,
    /// `"unauthenticated-tls"` or `"meshtls"`.
    pub authentication: String,

    /// The mesh identities accepted by a `meshtls` authorization
    /// (`*`, `*.suffix` or an exact identity).
    pub identities: Vec<String>,

    /// The source networks from which the authorization accepts clients.
    pub networks: Vec<String>,

    /// Whether the described client (if any) satisfies this authorization.
    /// Always `true` when no concrete client was provided.
    pub satisfied: bool,

    /// Human-readable reasons the authorization was not satisfied by the
    /// described client. Empty when satisfied or when no client was given.
    pub unsatisfied_reasons: Vec<String>,
}

/// The result of a dry-run evaluation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DryRunResponse {
    /// The resourceVersion of the index snapshot at which the evaluation ran.
    /// All matched policies in this response were read at this exact revision.
    pub resource_version: u64,

    pub namespace: String,
    pub pod: String,
    pub port: u16,

    /// Whether a concrete client was described in the request.
    pub client_provided: bool,

    pub server: MatchedServer,
    pub decision: DryRunDecision,
    pub authorizations: Vec<MatchedAuthorization>,

    /// The union of mesh identities required by the matched authorizations,
    /// deduplicated and sorted.
    pub required_identities: Vec<String>,

    /// Why the request would be denied (empty unless the decision is `deny`).
    pub deny_reasons: Vec<String>,
}

/// Errors that can occur during a dry-run evaluation.
#[derive(Debug, thiserror::Error)]
pub enum DryRunError {
    #[error("port {0} must be between 1 and 65535")]
    InvalidPort(u16),

    #[error("namespace {0} is not indexed")]
    NamespaceNotFound(String),

    #[error("pod {pod}.{namespace} is not indexed")]
    PodNotFound { namespace: String, pod: String },
}

impl DryRunError {
    /// Indicates whether the error is a missing-workload lookup (HTTP 404), as
    /// opposed to a bad request (HTTP 400).
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            DryRunError::NamespaceNotFound(_) | DryRunError::PodNotFound { .. }
        )
    }
}

/// A live `Server` that a not-yet-applied candidate `ServerAuthorization`
/// would select.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SelectedServer {
    pub name: String,
    pub resource_version: Option<String>,
    pub port: String,
    pub protocol: String,
}

/// The result of evaluating a candidate `ServerAuthorization` (e.g. one
/// received in a server-side `dryRun` admission request) against the live
/// servers without writing it to the cluster.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerAuthorizationPreview {
    /// The resourceVersion of the index snapshot used for the preview.
    pub resource_version: u64,

    pub namespace: String,
    pub name: String,

    /// The `metadata.resourceVersion` carried by the candidate object itself.
    pub candidate_resource_version: Option<String>,

    pub authentication: String,
    pub identities: Vec<String>,
    pub networks: Vec<String>,

    /// The live servers the candidate ServerAuthorization currently selects.
    pub selected_servers: Vec<SelectedServer>,
}

// === impl Index ===

impl Index {
    /// Evaluates inbound authorization for a hypothetical
    /// (`namespace`, `pod`, `port`, `client`) tuple against a consistent
    /// snapshot of the index.
    ///
    /// The caller must hold the index read lock for the duration of the call so
    /// that concurrent policy updates cannot interleave with the evaluation.
    pub fn dry_run(&self, request: DryRunRequest) -> Result<DryRunResponse, DryRunError> {
        let port = NonZeroU16::try_from(request.port)
            .map_err(|_| DryRunError::InvalidPort(request.port))?;

        // This value, and every policy inspected below, come from the same
        // locked snapshot.
        let revision = self.revision;

        let namespace = self
            .namespaces
            .by_ns
            .get(&request.namespace)
            .ok_or_else(|| DryRunError::NamespaceNotFound(request.namespace.clone()))?;
        let pod =
            namespace
                .pods
                .by_name
                .get(&request.pod)
                .ok_or_else(|| DryRunError::PodNotFound {
                    namespace: request.namespace.clone(),
                    pod: request.pod.clone(),
                })?;

        let (client, client_identity) = match request.client {
            Some(ref client) => {
                let identity = client.service_account.as_ref().map(|sa| {
                    let ns = client
                        .namespace
                        .as_deref()
                        .unwrap_or(request.namespace.as_str());
                    self.cluster_info.service_account_identity(ns, sa)
                });
                (Some(client), identity)
            }
            None => (None, None),
        };
        let client_provided = client.is_some();

        let mut deny_reasons = Vec::new();
        let mut required_identities = BTreeSet::new();

        // Resolve the server in effect for the port and its authorizations.
        let (server, authorizations) = match Self::selected_server(pod, &namespace.policy, port) {
            Some((name, srv)) => {
                let server = MatchedServer {
                    kind: "Server".to_string(),
                    name: name.clone(),
                    resource_version: srv.resource_version.clone(),
                    protocol: protocol_str(&srv.protocol).to_string(),
                    port: port.get(),
                };
                let authorizations =
                    namespace
                        .policy
                        .client_authzs(name, srv, &self.authentications);
                if authorizations.is_empty() {
                    deny_reasons.push(format!(
                        "Server \"{name}\" is not selected by any ServerAuthorization or \
                         AuthorizationPolicy; all traffic is denied",
                    ));
                }
                (server, authorizations)
            }
            None => {
                let default =
                    effective_default_policy(&pod.meta.settings, port, &self.cluster_info);
                let server = MatchedServer {
                    kind: "Default".to_string(),
                    name: default.as_str().to_string(),
                    resource_version: None,
                    protocol: "default".to_string(),
                    port: port.get(),
                };
                let authorizations = default.default_authzs(&self.cluster_info);
                if matches!(default, DefaultPolicy::Deny) {
                    deny_reasons.push(format!(
                        "no Server selects port {} and the effective default inbound policy is \
                         \"deny\"; all traffic is denied",
                        port.get(),
                    ));
                }
                (server, authorizations)
            }
        };

        // Evaluate each authorization deterministically.
        let mut entries = authorizations.iter().collect::<Vec<_>>();
        entries.sort_by_key(|(r, _)| ref_sort_key(r));

        let mut matched = Vec::with_capacity(entries.len());
        let mut allows = false;
        let mut audits = false;
        for (reference, authz) in entries {
            let resource_version = self.authorization_resource_version(namespace, reference);
            let summary = evaluate_authorization(
                reference,
                authz,
                resource_version,
                client,
                client_identity.as_deref(),
                &self.cluster_info,
            );

            for id in &summary.identities {
                required_identities.insert(id.clone());
            }

            let relevant = if summary.kind == "default" && summary.name == "audit" {
                &mut audits
            } else {
                &mut allows
            };
            if !client_provided || summary.satisfied {
                *relevant = true;
            } else {
                for reason in &summary.unsatisfied_reasons {
                    deny_reasons.push(format!("{} \"{}\": {}", summary.kind, summary.name, reason));
                }
            }

            matched.push(summary);
        }

        let decision = if allows {
            DryRunDecision::Allow
        } else if audits {
            DryRunDecision::Audit
        } else {
            DryRunDecision::Deny
        };

        Ok(DryRunResponse {
            resource_version: revision,
            namespace: request.namespace,
            pod: request.pod,
            port: request.port,
            client_provided,
            server,
            decision,
            authorizations: matched,
            required_identities: required_identities.into_iter().collect(),
            deny_reasons,
        })
    }

    /// Evaluates a candidate `ServerAuthorization` against the live index
    /// without applying it: reports which live servers its selector selects and
    /// which identities/networks it requires. Used for server-side `dryRun`
    /// admission requests.
    pub fn preview_server_authorization(
        &self,
        saz: linkerd_policy_controller_k8s_api::policy::ServerAuthorization,
    ) -> anyhow::Result<ServerAuthorizationPreview> {
        let namespace = saz.metadata.namespace.clone().unwrap_or_default();
        let name = saz.name_unchecked();
        let candidate_resource_version = saz.metadata.resource_version.clone();
        let candidate = ServerAuthz::from_resource(saz, &self.cluster_info)?;

        let revision = self.revision;

        let mut selected_servers = Vec::new();
        if let Some(ns) = self.namespaces.by_ns.get(&namespace) {
            let mut servers = ns.policy.servers.iter().collect::<Vec<_>>();
            servers.sort_by(|(an, asrv), (bn, bsrv)| {
                asrv.created_at
                    .cmp(&bsrv.created_at)
                    .then_with(|| an.cmp(bn))
            });
            for (srv_name, srv) in servers {
                if candidate.server_selector.selects(srv_name, &srv.labels) {
                    selected_servers.push(SelectedServer {
                        name: srv_name.clone(),
                        resource_version: srv.resource_version.clone(),
                        port: port_str(&srv.port_ref),
                        protocol: protocol_str(&srv.protocol).to_string(),
                    });
                }
            }
        }

        let (authentication, identities, networks) =
            authentication_summary(&candidate.authz, &self.cluster_info);

        Ok(ServerAuthorizationPreview {
            resource_version: revision,
            namespace,
            name,
            candidate_resource_version,
            authentication,
            identities,
            networks,
            selected_servers,
        })
    }

    /// Selects the first Server that selects the pod port, applying the same
    /// creation-timestamp/name precedence used when indexing.
    fn selected_server<'a>(
        pod: &Pod,
        policy: &'a PolicyIndex,
        port: NonZeroU16,
    ) -> Option<(&'a String, &'a server_index::Server)> {
        let mut servers = policy.servers.iter().collect::<Vec<_>>();
        servers.sort_by(|(an, asrv), (bn, bsrv)| {
            asrv.created_at
                .cmp(&bsrv.created_at)
                .then_with(|| an.cmp(bn))
        });
        for (name, srv) in servers {
            if let Selector::Pod(selector) = &srv.selector {
                if selector.matches(&pod.meta.labels)
                    && port_is_selected(&pod.port_names, &srv.port_ref, port)
                {
                    return Some((name, srv));
                }
            }
        }
        None
    }

    /// Looks up the Kubernetes resourceVersion of the object backing an
    /// authorization reference.
    fn authorization_resource_version(
        &self,
        namespace: &Namespace,
        reference: &AuthorizationRef,
    ) -> Option<String> {
        match reference {
            AuthorizationRef::Default(_) => None,
            AuthorizationRef::ServerAuthorization(name) => namespace
                .policy
                .server_authorizations
                .get(name)
                .and_then(|saz| saz.resource_version.clone()),
            AuthorizationRef::AuthorizationPolicy(name) => namespace
                .policy
                .authorization_policies
                .get(name)
                .and_then(|spec| spec.resource_version.clone()),
        }
    }
}

// === helpers ===

/// Computes the effective default policy for a pod port, including the
/// `proxy-require-identity-inbound-ports` annotation upgrade.
fn effective_default_policy(
    settings: &workload::Settings,
    port: NonZeroU16,
    cluster: &ClusterInfo,
) -> DefaultPolicy {
    let mut policy = settings.default_policy.unwrap_or(cluster.default_policy);
    if settings.require_id_ports.contains(&port) {
        if let DefaultPolicy::Allow {
            ref mut authenticated_only,
            ..
        } = policy
        {
            *authenticated_only = true;
        }
    }
    policy
}

/// Indicates whether a server port reference selects the given numeric port on
/// a pod (resolving named ports).
fn port_is_selected(
    port_names: &ahash::AHashMap<String, crate::ports::PortSet>,
    port_ref: &ServerPort,
    port: NonZeroU16,
) -> bool {
    match port_ref {
        ServerPort::Number(p) => *p == port,
        ServerPort::Name(name) => port_names
            .get(name)
            .map(|ports| ports.contains(&port))
            .unwrap_or(false),
    }
}

fn port_str(port_ref: &ServerPort) -> String {
    match port_ref {
        ServerPort::Number(port) => port.to_string(),
        ServerPort::Name(name) => format!("name:{name}"),
    }
}

fn protocol_str(protocol: &ProxyProtocol) -> &'static str {
    match protocol {
        ProxyProtocol::Detect { .. } => "detect",
        ProxyProtocol::Http1 => "HTTP/1",
        ProxyProtocol::Http2 => "HTTP/2",
        ProxyProtocol::Grpc => "gRPC",
        ProxyProtocol::Opaque => "opaque",
        ProxyProtocol::Tls => "TLS",
    }
}

fn ref_sort_key(reference: &AuthorizationRef) -> (u8, &str) {
    match reference {
        AuthorizationRef::Default(name) => (0, name),
        AuthorizationRef::ServerAuthorization(name) => (1, name),
        AuthorizationRef::AuthorizationPolicy(name) => (2, name),
    }
}

/// Produces the JSON-friendly summary of an authorization and, when a concrete
/// client is described, determines whether it satisfies the authorization.
fn evaluate_authorization(
    reference: &AuthorizationRef,
    authz: &ClientAuthorization,
    resource_version: Option<String>,
    client: Option<&DryRunClient>,
    client_identity: Option<&str>,
    cluster: &ClusterInfo,
) -> MatchedAuthorization {
    let (kind, name) = match reference {
        AuthorizationRef::Default(name) => ("default", name.to_string()),
        AuthorizationRef::ServerAuthorization(name) => ("ServerAuthorization", name.clone()),
        AuthorizationRef::AuthorizationPolicy(name) => ("AuthorizationPolicy", name.clone()),
    };

    // An empty network list is served to proxies as the cluster networks.
    let effective_networks = if authz.networks.is_empty() {
        cluster
            .networks
            .iter()
            .copied()
            .map(NetworkMatch::from)
            .collect::<Vec<_>>()
    } else {
        authz.networks.clone()
    };
    let networks = effective_networks
        .iter()
        .map(|network| network.net.to_string())
        .collect::<Vec<_>>();

    let mut unsatisfied_reasons = Vec::new();

    let network_ok = match client.and_then(|client| client.ip) {
        Some(ip) if !network_allows(&effective_networks, ip) => {
            unsatisfied_reasons.push(format!(
                "source IP {ip} is outside the authorized source network(s) {}",
                networks.join(", ")
            ));
            false
        }
        _ => true,
    };

    let (authentication, identities, authn_ok) = match &authz.authentication {
        ClientAuthentication::Unauthenticated => ("unauthenticated".to_string(), vec![], true),
        ClientAuthentication::TlsUnauthenticated => {
            let ok = match client {
                // Requirement-only mode: simply describe what is needed.
                None => true,
                Some(client) => client.ingress || client.service_account.is_some(),
            };
            if !ok {
                unsatisfied_reasons.push(
                    "client does not present mesh TLS; only unauthenticated TLS clients (e.g. a \
                     mesh ingress controller) are authorized"
                        .to_string(),
                );
            }
            ("unauthenticated-tls".to_string(), vec![], ok)
        }
        ClientAuthentication::TlsAuthenticated(required) => {
            let identities = required
                .iter()
                .map(|identity| identity.to_string())
                .collect::<Vec<_>>();
            let ok = match (client, client_identity) {
                (None, _) => true,
                (Some(_), Some(identity)) => required
                    .iter()
                    .any(|required| identity_matches(required, identity)),
                (Some(_), None) => false,
            };
            if !ok {
                unsatisfied_reasons.push(format!(
                    "client mesh identity is not authorized; one of {} is required",
                    identities.join(", ")
                ));
            }
            ("meshtls".to_string(), identities, ok)
        }
    };

    MatchedAuthorization {
        kind: kind.to_string(),
        name,
        resource_version,
        authentication,
        identities,
        networks,
        satisfied: network_ok && authn_ok,
        unsatisfied_reasons,
    }
}

fn authentication_summary(
    authz: &ClientAuthorization,
    cluster: &ClusterInfo,
) -> (String, Vec<String>, Vec<String>) {
    let networks = if authz.networks.is_empty() {
        cluster.networks.iter().map(|net| net.to_string()).collect()
    } else {
        authz
            .networks
            .iter()
            .map(|network| network.net.to_string())
            .collect()
    };
    match &authz.authentication {
        ClientAuthentication::Unauthenticated => ("unauthenticated".to_string(), vec![], networks),
        ClientAuthentication::TlsUnauthenticated => {
            ("unauthenticated-tls".to_string(), vec![], networks)
        }
        ClientAuthentication::TlsAuthenticated(identities) => (
            "meshtls".to_string(),
            identities
                .iter()
                .map(|identity| identity.to_string())
                .collect(),
            networks,
        ),
    }
}

/// Indicates whether `ip` is included by a network match after applying
/// exclusions.
fn network_allows(networks: &[NetworkMatch], ip: IpAddr) -> bool {
    networks.iter().any(|network| {
        network.net.contains(&ip) && !network.except.iter().any(|except| except.contains(&ip))
    })
}

/// Matches a concrete mesh identity against an exact or suffix identity
/// requirement.
///
/// A suffix requirement lists the trailing DNS labels the identity must have;
/// an empty suffix (`*`) matches any mesh identity.
fn identity_matches(required: &IdentityMatch, identity: &str) -> bool {
    match required {
        IdentityMatch::Exact(expected) => expected == identity,
        IdentityMatch::Suffix(suffix) => {
            if suffix.is_empty() {
                return true;
            }
            let labels = identity.split('.').collect::<Vec<_>>();
            if labels.len() < suffix.len() {
                return false;
            }
            suffix
                .iter()
                .zip(&labels[labels.len() - suffix.len()..])
                .all(|(required, actual)| required == actual)
        }
    }
}
