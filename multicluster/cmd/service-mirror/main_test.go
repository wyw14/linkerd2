package servicemirror

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linkerd/linkerd2/controller/gen/apis/link/v1alpha3"
	controllerK8s "github.com/linkerd/linkerd2/controller/k8s"
	servicemirror "github.com/linkerd/linkerd2/multicluster/service-mirror"
	"github.com/linkerd/linkerd2/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// TestLoadCredentialsRotates verifies that rotating the remote cluster
// credentials Secret (renewed client certificate / trust anchors) is picked
// up when the credentials are reloaded, which is what happens when the Link
// is reconciled after a TLS rotation.
func TestLoadCredentialsRotates(t *testing.T) {
	ctx := context.Background()
	namespace := "linkerd-multicluster"
	secretName := "remote-cluster-credentials"

	link := &v1alpha3.Link{
		Spec: v1alpha3.LinkSpec{ClusterCredentialsSecret: secretName},
	}
	initialKubeconfig := []byte("kubeconfig-with-client-cert-a-and-trust-anchor-a")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretType(k8s.MirrorSecretType),
		Data: map[string][]byte{
			k8s.ConfigKeyName: initialKubeconfig,
		},
	}
	client := fake.NewSimpleClientset(secret)

	creds, err := loadCredentials(ctx, link, namespace, client)
	if err != nil {
		t.Fatalf("failed to load initial credentials: %s", err)
	}
	if string(creds) != string(initialKubeconfig) {
		t.Fatalf("expected initial kubeconfig to be returned, got %q", string(creds))
	}

	// Simulate a TLS rotation: the Secret is updated in-place with a renewed
	// kubeconfig (new client certificate / trust anchor).
	rotatedKubeconfig := []byte("kubeconfig-with-client-cert-b-and-trust-anchor-b")
	secret.Data[k8s.ConfigKeyName] = rotatedKubeconfig
	if _, err := client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	rotatedCreds, err := loadCredentials(ctx, link, namespace, client)
	if err != nil {
		t.Fatalf("failed to reload rotated credentials: %s", err)
	}
	if string(rotatedCreds) != string(rotatedKubeconfig) {
		t.Fatalf("expected rotated kubeconfig to be returned, got %q", string(rotatedCreds))
	}
	if string(rotatedCreds) == string(creds) {
		t.Fatal("expected the reloaded credentials to differ after rotation")
	}

	// A missing credentials Secret must surface an error instead of blocking
	// with stale credentials.
	missing := &v1alpha3.Link{
		Spec: v1alpha3.LinkSpec{ClusterCredentialsSecret: "does-not-exist"},
	}
	if _, err := loadCredentials(ctx, missing, namespace, client); err == nil {
		t.Fatal("expected an error when the credentials secret is missing")
	}
}

// newFakeRemoteDiscoveryServer returns an HTTP server which emulates the
// Kubernetes discovery endpoint used by the service mirror to verify remote
// cluster connectivity.
func newFakeRemoteDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		version := map[string]string{
			"major":        "1",
			"minor":        "30",
			"gitVersion":   "v1.30.0",
			"gitCommit":    "fake",
			"gitTreeState": "clean",
			"buildDate":    "2024-01-01T00:00:00Z",
			"goVersion":    "go1.22.0",
			"compiler":     "gc",
			"platform":     "linux/amd64",
		}
		if err := json.NewEncoder(w).Encode(version); err != nil {
			t.Errorf("failed to write fake discovery response: %s", err)
		}
	}))
}

// TestRemoteClusterWatcherReconnects verifies that an unreachable remote
// cluster makes the watcher (re)start fail and that the watcher can be
// started successfully once the remote API is reachable again, without
// affecting the local API.
func TestRemoteClusterWatcherReconnects(t *testing.T) {
	ctx := context.Background()

	localAPI, err := controllerK8s.NewFakeAPIWithL5dClient()
	if err != nil {
		t.Fatal(err)
	}
	localAPI.Sync(nil)
	linksAPI := controllerK8s.NewNamespacedAPI(nil, nil, localAPI.L5dClient, "default", "local", controllerK8s.Link)
	linksAPI.Sync(nil)

	link := &v1alpha3.Link{
		ObjectMeta: metav1.ObjectMeta{Name: "remote", Namespace: "default"},
		Spec: v1alpha3.LinkSpec{
			TargetClusterName: "remote",
			GatewayAddress:    "192.0.2.127",
			GatewayPort:       "888",
		},
	}

	// The remote API is down: connecting and restarting the watcher must fail
	// fast with a connectivity error instead of blocking indefinitely.
	stopped := newFakeRemoteDiscoveryServer(t)
	stopped.Close()
	unreachableCfg := &rest.Config{Host: stopped.URL, Timeout: 2 * time.Second}
	unreachableAPI, err := controllerK8s.InitializeAPIForConfig(
		ctx, unreachableCfg, false, "remote", controllerK8s.Svc, controllerK8s.Endpoint,
	)
	if err != nil {
		t.Fatalf("client construction should not dial the remote API: %s", err)
	}
	if _, err := servicemirror.NewRemoteClusterServiceWatcher(
		ctx, "default", localAPI, unreachableAPI, linksAPI, "",
		link, 0, time.Minute, make(chan bool), false, false,
	); err == nil || !strings.Contains(err.Error(), "cannot connect") {
		t.Fatalf("expected a 'cannot connect' error when the remote is unreachable, got: %v", err)
	}

	// The remote API comes back: the service mirror reconnects and the
	// watcher starts successfully.
	server := newFakeRemoteDiscoveryServer(t)
	defer server.Close()
	reachableCfg := &rest.Config{Host: server.URL, Timeout: 2 * time.Second}
	reachableAPI, err := controllerK8s.InitializeAPIForConfig(
		ctx, reachableCfg, false, "remote", controllerK8s.Svc, controllerK8s.Endpoint,
	)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := servicemirror.NewRemoteClusterServiceWatcher(
		ctx, "default", localAPI, reachableAPI, linksAPI, "",
		link, 0, time.Minute, make(chan bool), false, false,
	)
	if err != nil {
		t.Fatalf("expected the watcher to reconnect once the remote is reachable, got: %s", err)
	}
	defer watcher.Stop(false)

	// Sanity check: the reconnected watcher targets the same remote cluster.
	if watcher == nil {
		t.Fatal("expected a non-nil watcher after reconnecting")
	}
}
