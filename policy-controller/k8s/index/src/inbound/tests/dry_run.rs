//! Tests for read-only dry-run authorization evaluation, covering ingress
//! clients, ServiceAccount identities, cross-namespace references, and
//! resourceVersion consistency under concurrent policy updates.

use super::*;
use crate::inbound::{DryRunClient, DryRunDecision, DryRunRequest, ServerAuthorizationPreview};
use kubert::index::IndexNamespacedResource;
use linkerd_policy_controller_k8s_api::policy::server_authorization::{
    Client, MeshTls, Network as ClientNetwork, Server as AuthzServer, ServiceAccountRef,
};
use std::num::NonZeroU16;

const PORT: u16 = 8080;

fn request(ns: &str, pod: &str, client: Option<DryRunClient>) -> DryRunRequest {
    DryRunRequest {
        namespace: ns.to_string(),
        pod: pod.to_string(),
        port: PORT,
        client,
    }
}

fn client(
    ns: Option<&str>,
    service_account: Option<&str>,
    ip: Option<&str>,
    ingress: bool,
) -> DryRunClient {
    DryRunClient {
        namespace: ns.map(str::to_string),
        service_account: service_account.map(str::to_string),
        ip: ip.and_then(|ip| ip.parse().ok()),
        ingress,
    }
}

fn indexed_pod(test: &TestConfig) {
    let mut pod = mk_pod("ns-0", "pod-0", Some(("app", http_port())));
    pod.labels_mut()
        .insert("app".to_string(), "app-0".to_string());
    test.index.write().apply(pod);
}

fn http_port() -> Vec<ContainerPort> {
    vec![ContainerPort {
        name: Some("http".to_string()),
        container_port: PORT as i32,
        protocol: Some("TCP".to_string()),
        ..Default::default()
    }]
}

fn indexed_server(test: &TestConfig, resource_version: Option<&str>) {
    let mut server = mk_server(
        "ns-0",
        "srv-8080",
        Port::Number(NonZeroU16::try_from(PORT).unwrap()),
        Some(("app", "app-0")),
        Some(("app", "app-0")),
        Some(k8s::policy::server::ProxyProtocol::Http1),
    );
    server.metadata.resource_version = resource_version.map(str::to_string);
    test.index.write().apply(server);
}

fn server_authorization(
    name: &str,
    resource_version: Option<&str>,
    client: Client,
) -> k8s::policy::ServerAuthorization {
    server_authorization_for("ns-0", name, resource_version, client)
}

fn server_authorization_for(
    ns: &str,
    name: &str,
    resource_version: Option<&str>,
    client: Client,
) -> k8s::policy::ServerAuthorization {
    k8s::policy::ServerAuthorization {
        metadata: k8s::ObjectMeta {
            namespace: Some(ns.to_string()),
            name: Some(name.to_string()),
            resource_version: resource_version.map(str::to_string),
            ..Default::default()
        },
        spec: k8s::policy::ServerAuthorizationSpec {
            server: AuthzServer {
                name: Some("srv-8080".to_string()),
                selector: None,
            },
            client,
        },
    }
}

fn unauthenticated_client() -> Client {
    Client {
        networks: None,
        unauthenticated: true,
        mesh_tls: None,
    }
}

fn service_account_client(service_accounts: Vec<ServiceAccountRef>) -> Client {
    Client {
        networks: None,
        unauthenticated: false,
        mesh_tls: Some(MeshTls {
            unauthenticated_tls: false,
            identities: None,
            service_accounts: Some(service_accounts),
        }),
    }
}

fn sa_ref(namespace: Option<&str>, name: &str) -> ServiceAccountRef {
    ServiceAccountRef {
        namespace: namespace.map(str::to_string),
        name: name.to_string(),
    }
}

fn eval(test: &TestConfig, client: Option<DryRunClient>) -> crate::inbound::DryRunResponse {
    test.index
        .read()
        .dry_run(request("ns-0", "pod-0", client))
        .expect("dry-run must succeed for an indexed pod")
}

#[test]
fn dry_run_default_deny_reports_reason_and_stable_revision() {
    let test = TestConfig::from_default_policy(DefaultPolicy::Deny);
    indexed_pod(&test);

    let revision = test.index.read().revision();

    let response = eval(&test, None);
    assert_eq!(response.decision, DryRunDecision::Deny);
    assert_eq!(response.server.kind, "Default");
    assert_eq!(response.server.name, "deny");
    assert_eq!(response.resource_version, revision);
    assert!(response.authorizations.is_empty());
    assert!(
        response
            .deny_reasons
            .join(" ")
            .contains("default inbound policy is \"deny\""),
        "unexpected deny reasons: {:?}",
        response.deny_reasons
    );

    // Read-only evaluations do not bump the revision.
    let again = eval(&test, None);
    assert_eq!(again.resource_version, revision);
    assert_eq!(test.index.read().revision(), revision);
}

#[test]
fn dry_run_named_server_without_authorization_is_denied() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, Some("100"));

    let response = eval(&test, None);
    assert_eq!(response.decision, DryRunDecision::Deny);
    assert_eq!(response.server.kind, "Server");
    assert_eq!(response.server.name, "srv-8080");
    assert_eq!(response.server.resource_version.as_deref(), Some("100"));
    assert!(
        response
            .deny_reasons
            .join(" ")
            .contains("not selected by any ServerAuthorization"),
        "unexpected deny reasons: {:?}",
        response.deny_reasons
    );
}

#[test]
fn dry_run_matches_server_authorization_and_reports_resource_versions() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, Some("100"));

    // The named server alone denies.
    assert_eq!(eval(&test, None).decision, DryRunDecision::Deny);
    let revision_without_authz = test.index.read().revision();

    test.index.write().apply(server_authorization(
        "authz-web",
        Some("200"),
        unauthenticated_client(),
    ));

    assert!(test.index.read().revision() > revision_without_authz);

    // An empty `client.networks` list is served to proxies as the cluster
    // networks (192.0.2.0/24 in the test config).
    let response = eval(&test, Some(client(None, None, Some("192.0.2.5"), false)));
    assert_eq!(response.decision, DryRunDecision::Allow);
    assert_eq!(response.authorizations.len(), 1);
    let matched = &response.authorizations[0];
    assert_eq!(matched.kind, "ServerAuthorization");
    assert_eq!(matched.name, "authz-web");
    assert_eq!(matched.resource_version.as_deref(), Some("200"));
    assert_eq!(matched.authentication, "unauthenticated");
    assert!(matched.satisfied);
    assert!(matched.unsatisfied_reasons.is_empty());

    // The response attributes each piece to a single revision.
    assert_eq!(response.server.resource_version.as_deref(), Some("100"));
    assert_eq!(response.resource_version, test.index.read().revision());
}

#[test]
fn dry_run_service_account_identity_is_required() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, None);
    test.index.write().apply(server_authorization(
        "authz-web",
        None,
        service_account_client(vec![sa_ref(None, "web")]),
    ));

    let expected_identity = test.cluster.service_account_identity("ns-0", "web");

    // Requirement-only response reports the identity.
    let described = eval(&test, None);
    assert_eq!(described.decision, DryRunDecision::Allow);
    assert_eq!(
        described.required_identities,
        vec![expected_identity.clone()]
    );

    // The matching ServiceAccount is admitted.
    let allowed = eval(&test, Some(client(Some("ns-0"), Some("web"), None, false)));
    assert_eq!(allowed.decision, DryRunDecision::Allow);
    assert!(allowed.authorizations[0].satisfied);

    // Another ServiceAccount is denied and told what is required.
    let denied = eval(
        &test,
        Some(client(Some("ns-0"), Some("other"), None, false)),
    );
    assert_eq!(denied.decision, DryRunDecision::Deny);
    assert!(!denied.authorizations[0].satisfied);
    assert!(
        denied.deny_reasons.join(" ").contains(&expected_identity),
        "deny reasons must name the required identity: {:?}",
        denied.deny_reasons
    );
}

#[test]
fn dry_run_service_account_in_another_namespace() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, None);
    test.index.write().apply(server_authorization(
        "authz-peer",
        None,
        service_account_client(vec![sa_ref(Some("ns-1"), "peer")]),
    ));

    let peer_identity = test.cluster.service_account_identity("ns-1", "peer");
    let local_identity = test.cluster.service_account_identity("ns-0", "peer");

    let described = eval(&test, None);
    assert_eq!(described.required_identities, vec![peer_identity.clone()]);

    // The ServiceAccount in the referenced namespace is admitted.
    let peer = eval(&test, Some(client(Some("ns-1"), Some("peer"), None, false)));
    assert_eq!(peer.decision, DryRunDecision::Allow);

    // The same ServiceAccount name in the target namespace does not match.
    let local = eval(&test, Some(client(Some("ns-0"), Some("peer"), None, false)));
    assert_eq!(local.decision, DryRunDecision::Deny);
    assert!(
        local.deny_reasons.join(" ").contains(&peer_identity),
        "deny reasons must require the cross-namespace identity: {:?}",
        local.deny_reasons
    );
    assert_ne!(peer_identity, local_identity);
}

#[test]
fn dry_run_authorization_policy_with_cross_namespace_meshtls_authentication() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, Some("100"));

    let remote_identity = "prom.ns-1.serviceaccount.identity.linkerd.cluster.example.com";

    // An AuthorizationPolicy in ns-0 that requires a MeshTLSAuthentication
    // living in ns-1.
    test.index.write().apply(mk_authorization_policy(
        "ns-0",
        "authz-prom",
        Some("srv-8080"),
        [NamespacedTargetRef {
            group: Some("policy.linkerd.io".to_string()),
            kind: "MeshTLSAuthentication".to_string(),
            name: "remote-authn".to_string(),
            namespace: Some("ns-1".to_string()),
        }],
    ));

    // Without the cross-namespace authentication resource, the policy cannot be
    // built and is ignored: nothing selects the server.
    let unresolved = eval(&test, None);
    assert_eq!(unresolved.decision, DryRunDecision::Deny);
    assert!(unresolved
        .deny_reasons
        .join(" ")
        .contains("not selected by any ServerAuthorization"));

    test.index.write().apply(mk_meshtls_authentication(
        "ns-1",
        "remote-authn",
        vec![remote_identity.to_string()],
        vec![],
    ));

    let resolved = eval(&test, None);
    assert_eq!(resolved.decision, DryRunDecision::Allow);
    assert_eq!(
        resolved.required_identities,
        vec![remote_identity.to_string()]
    );
    let matched = &resolved.authorizations[0];
    assert_eq!(matched.kind, "AuthorizationPolicy");
    assert_eq!(matched.name, "authz-prom");
    assert_eq!(matched.authentication, "meshtls");

    let allowed = eval(&test, Some(client(Some("ns-1"), Some("prom"), None, false)));
    assert_eq!(allowed.decision, DryRunDecision::Allow);
    let denied = eval(
        &test,
        Some(client(Some("ns-1"), Some("other"), None, false)),
    );
    assert_eq!(denied.decision, DryRunDecision::Deny);

    // Deleting the cross-namespace authentication invalidates the policy again,
    // demonstrating that cross-namespace references are resolved live.
    <Index as IndexNamespacedResource<k8s::policy::MeshTLSAuthentication>>::delete(
        &mut *test.index.write(),
        "ns-1".to_string(),
        "remote-authn".to_string(),
    );
    let deleted = eval(&test, Some(client(Some("ns-1"), Some("prom"), None, false)));
    assert_eq!(deleted.decision, DryRunDecision::Deny);
}

#[test]
fn dry_run_ingress_with_unauthenticated_tls() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, None);
    test.index.write().apply(server_authorization(
        "authz-ingress",
        None,
        Client {
            networks: None,
            unauthenticated: false,
            mesh_tls: Some(MeshTls {
                unauthenticated_tls: true,
                identities: None,
                service_accounts: None,
            }),
        },
    ));

    // A mesh ingress controller terminating TLS is admitted.
    let ingress = eval(&test, Some(client(None, None, Some("192.0.2.5"), true)));
    assert_eq!(ingress.decision, DryRunDecision::Allow);
    assert_eq!(
        ingress.authorizations[0].authentication,
        "unauthenticated-tls"
    );

    // A meshed workload with its own identity is also admitted.
    let meshed = eval(&test, Some(client(Some("ns-0"), Some("web"), None, false)));
    assert_eq!(meshed.decision, DryRunDecision::Allow);

    // A plain, non-ingress client that does not use mesh TLS is rejected,
    // even from a cluster network.
    let plain = eval(&test, Some(client(None, None, Some("192.0.2.5"), false)));
    assert_eq!(plain.decision, DryRunDecision::Deny);
    assert!(
        plain
            .deny_reasons
            .join(" ")
            .contains("unauthenticated TLS clients (e.g. a mesh ingress controller)"),
        "unexpected deny reasons: {:?}",
        plain.deny_reasons
    );
}

#[test]
fn dry_run_ingress_is_subject_to_network_restrictions() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, None);
    test.index.write().apply(server_authorization(
        "authz-ingress",
        None,
        Client {
            networks: Some(vec![ClientNetwork {
                cidr: "10.0.0.0/8".parse().unwrap(),
                except: None,
            }]),
            unauthenticated: true,
            mesh_tls: None,
        },
    ));

    // Ingress traffic from the authorized network is allowed.
    let allowed = eval(&test, Some(client(None, None, Some("10.1.2.3"), true)));
    assert_eq!(allowed.decision, DryRunDecision::Allow);

    // Ingress traffic from outside the network is denied for that reason.
    let blocked = eval(&test, Some(client(None, None, Some("8.8.8.8"), true)));
    assert_eq!(blocked.decision, DryRunDecision::Deny);
    assert!(
        blocked
            .deny_reasons
            .join(" ")
            .contains("outside the authorized source network"),
        "unexpected deny reasons: {:?}",
        blocked.deny_reasons
    );
}

#[test]
fn dry_run_reports_independent_snapshot_versions_on_update() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, Some("s1"));

    test.index.write().apply(server_authorization(
        "authz-web",
        Some("a1"),
        service_account_client(vec![sa_ref(None, "web")]),
    ));
    let before = eval(&test, None);
    assert_eq!(
        before.authorizations[0].resource_version.as_deref(),
        Some("a1")
    );
    let revision_before = before.resource_version;

    // A concurrent policy update arrives: the same ServerAuthorization changes
    // identity requirements and resourceVersion.
    test.index.write().apply(server_authorization(
        "authz-web",
        Some("a2"),
        service_account_client(vec![sa_ref(None, "web-v2")]),
    ));

    let after = eval(&test, None);
    assert!(after.resource_version > revision_before);
    assert_eq!(
        after.authorizations[0].resource_version.as_deref(),
        Some("a2")
    );
    assert_eq!(
        after.required_identities,
        vec![test.cluster.service_account_identity("ns-0", "web-v2")]
    );

    // The earlier response is an owned snapshot: it is unaffected by the update,
    // i.e. versions never mix within or across evaluations.
    assert_eq!(before.resource_version, revision_before);
    assert_eq!(
        before.authorizations[0].resource_version.as_deref(),
        Some("a1")
    );
    assert_eq!(
        before.required_identities,
        vec![test.cluster.service_account_identity("ns-0", "web")]
    );
}

#[test]
fn dry_run_remains_consistent_under_concurrent_updates() {
    let test = std::sync::Arc::new(TestConfig::default());
    indexed_pod(&test);
    indexed_server(&test, Some("s1"));

    let mut handles = Vec::new();

    // Writers continuously apply and delete distinct ServerAuthorizations.
    for writer in 0..3 {
        let index = test.index.clone();
        handles.push(std::thread::spawn(move || {
            let name = format!("authz-{writer}");
            for _ in 0..50 {
                index
                    .write()
                    .apply(server_authorization(&name, None, unauthenticated_client()));
                <Index as IndexNamespacedResource<k8s::policy::ServerAuthorization>>::delete(
                    &mut *index.write(),
                    "ns-0".to_string(),
                    name.clone(),
                );
            }
        }));
    }

    // Readers evaluate concurrently. Each reader must observe a single coherent
    // revision: revisions are monotonic, the matched server never changes and
    // every decision/authorization pairing is internally consistent.
    for _ in 0..4 {
        let index = test.index.clone();
        handles.push(std::thread::spawn(move || {
            let mut last_revision = 0;
            for _ in 0..200 {
                let response = index
                    .read()
                    .dry_run(request(
                        "ns-0",
                        "pod-0",
                        Some(client(None, None, None, false)),
                    ))
                    .expect("pod is indexed");
                assert!(response.resource_version >= last_revision);
                last_revision = response.resource_version;

                assert_eq!(response.server.kind, "Server");
                assert_eq!(response.server.name, "srv-8080");
                match response.decision {
                    DryRunDecision::Allow => assert!(!response.authorizations.is_empty()),
                    DryRunDecision::Deny => {
                        // Denial can only happen because no authorization was
                        // momentarily present.
                        assert!(response.authorizations.is_empty());
                        assert!(response
                            .deny_reasons
                            .join(" ")
                            .contains("not selected by any ServerAuthorization"));
                    }
                    DryRunDecision::Audit => panic!("no audit policy is configured"),
                }
                for authz in &response.authorizations {
                    assert_eq!(authz.kind, "ServerAuthorization");
                    assert!(["authz-0", "authz-1", "authz-2"].contains(&authz.name.as_str()));
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("dry-run worker must not panic");
    }
}

#[test]
fn preview_server_authorization_does_not_modify_index() {
    let test = TestConfig::default();
    indexed_pod(&test);
    indexed_server(&test, Some("100"));

    // A candidate ServerAuthorization that is never applied selects the live
    // server and reports the identity it would require.
    let candidate = server_authorization(
        "candidate",
        Some("candidate-rv"),
        service_account_client(vec![sa_ref(None, "web")]),
    );
    let preview: ServerAuthorizationPreview = test
        .index
        .read()
        .preview_server_authorization(candidate)
        .expect("candidate must be valid");

    assert_eq!(
        preview.candidate_resource_version.as_deref(),
        Some("candidate-rv")
    );
    assert_eq!(preview.authentication, "meshtls");
    assert_eq!(
        preview.identities,
        vec![test.cluster.service_account_identity("ns-0", "web")]
    );
    assert_eq!(preview.selected_servers.len(), 1);
    assert_eq!(preview.selected_servers[0].name, "srv-8080");
    assert_eq!(
        preview.selected_servers[0].resource_version.as_deref(),
        Some("100")
    );
    assert_eq!(preview.selected_servers[0].port, PORT.to_string());
    assert_eq!(preview.resource_version, test.index.read().revision());

    // The preview did not write anything: the server still has no
    // authorization, so a dry-run is denied.
    assert_eq!(eval(&test, None).decision, DryRunDecision::Deny);

    // A candidate whose selector matches nothing reports an empty selection.
    let mismatch = k8s::policy::ServerAuthorization {
        metadata: k8s::ObjectMeta {
            namespace: Some("ns-0".to_string()),
            name: Some("mismatch".to_string()),
            ..Default::default()
        },
        spec: k8s::policy::ServerAuthorizationSpec {
            server: AuthzServer {
                name: None,
                selector: Some(Some(("app", "does-not-exist")).into_iter().collect()),
            },
            client: unauthenticated_client(),
        },
    };
    let preview = test
        .index
        .read()
        .preview_server_authorization(mismatch)
        .expect("candidate must be valid");
    assert!(preview.selected_servers.is_empty());
    assert_eq!(eval(&test, None).decision, DryRunDecision::Deny);
}

#[test]
fn dry_run_errors_for_unindexed_targets() {
    let test = TestConfig::default();

    let error = test
        .index
        .read()
        .dry_run(request("missing-ns", "pod-0", None))
        .expect_err("namespace is not indexed");
    assert!(matches!(
        error,
        crate::inbound::DryRunError::NamespaceNotFound(ref ns) if ns == "missing-ns"
    ));
    assert!(error.is_not_found());

    indexed_pod(&test);
    let error = test
        .index
        .read()
        .dry_run(request("ns-0", "missing-pod", None))
        .expect_err("pod is not indexed");
    assert!(matches!(
        error,
        crate::inbound::DryRunError::PodNotFound { .. }
    ));
    assert!(error.is_not_found());

    let mut bad = request("ns-0", "pod-0", None);
    bad.port = 0;
    let error = test
        .index
        .read()
        .dry_run(bad)
        .expect_err("port 0 is invalid");
    assert!(matches!(error, crate::inbound::DryRunError::InvalidPort(0)));
    assert!(!error.is_not_found());
}
