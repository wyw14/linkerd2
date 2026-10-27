package servicemirror

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/linkerd/linkerd2/controller/gen/apis/link/v1alpha3"
	"github.com/linkerd/linkerd2/controller/k8s"
	consts "github.com/linkerd/linkerd2/pkg/k8s"
	logging "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

const (
	statusTestLinkName  = "remote-link"
	statusTestNamespace = "default"
)

// runStatusEnvironment mirrors testEnvironment.runEnvironment but creates
// the Link resource in the fake CRD client so that the watcher status patches
// succeed and can be asserted on. The refreshed Link is returned together
// with the local API.
func runStatusEnvironment(t *testing.T, te *testEnvironment, seedStatus *v1alpha3.LinkStatus) (*k8s.API, *v1alpha3.Link) {
	t.Helper()

	remoteAPI, err := k8s.NewFakeAPI(te.remoteResources...)
	if err != nil {
		t.Fatal(err)
	}
	localAPI, err := k8s.NewFakeAPIWithL5dClient(te.localResources...)
	if err != nil {
		t.Fatal(err)
	}
	linksAPI := k8s.NewNamespacedAPI(nil, nil, localAPI.L5dClient, statusTestNamespace, "local", k8s.Link)
	remoteAPI.Sync(nil)
	localAPI.Sync(nil)
	linksAPI.Sync(nil)

	link := te.link.DeepCopy()
	link.Name = statusTestLinkName
	link.Namespace = statusTestNamespace
	if seedStatus != nil {
		link.Status = *seedStatus
	}
	_, err = localAPI.L5dClient.LinkV1alpha3().Links(statusTestNamespace).Create(
		context.Background(), link, metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	limiter := workqueue.DefaultTypedControllerRateLimiter[any]()
	q := workqueue.NewTypedRateLimitingQueue(limiter)
	watcher := &RemoteClusterServiceWatcher{
		link:                    link,
		remoteAPIClient:         remoteAPI,
		localAPIClient:          localAPI,
		linksAPIClient:          linksAPI,
		log:                     logging.WithFields(logging.Fields{"cluster": clusterName}),
		eventsQueue:             q,
		rateLimiter:             limiter,
		requeueLimit:            0,
		headlessServicesEnabled: true,
	}
	watcher.setGatewayAlive(true)

	for _, ev := range te.events {
		q.Add(ev)
	}
	for range te.events {
		watcher.processNextEvent(context.Background())
	}

	localAPI.Sync(nil)
	remoteAPI.Sync(nil)

	refreshed, err := localAPI.L5dClient.LinkV1alpha3().Links(statusTestNamespace).Get(
		context.Background(), statusTestLinkName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return localAPI, refreshed
}

func getMirrorStatus(t *testing.T, link *v1alpha3.Link, namespace, name string) v1alpha3.ServiceStatus {
	t.Helper()
	status := getServiceStatus(name, namespace, link.Status.MirrorServices)
	if status == nil {
		t.Fatalf("expected mirror status for %s/%s, got: %+v", namespace, name, link.Status.MirrorServices)
	}
	return *status
}

func assertNoMirrorStatus(t *testing.T, link *v1alpha3.Link, namespace, name string) {
	t.Helper()
	if status := getServiceStatus(name, namespace, link.Status.MirrorServices); status != nil {
		t.Fatalf("expected mirror status for %s/%s to be removed, got: %+v", namespace, name, status)
	}
}

// TestMirrorStatusOnExport ensures that a successfully imported service
// records its imported remote version, its endpoint count and a clean error
// state.
func TestMirrorStatusOnExport(t *testing.T) {
	_, link := runStatusEnvironment(t, createExportedService, nil)

	if len(link.Status.MirrorServices) != 1 {
		t.Fatalf("expected 1 mirror status entry, got %d: %+v", len(link.Status.MirrorServices), link.Status.MirrorServices)
	}
	status := getMirrorStatus(t, link, "ns1", "service-one")
	if status.ImportedVersion != "111" {
		t.Fatalf("expected imported version '111', got '%s'", status.ImportedVersion)
	}
	if status.Endpoints != 1 {
		t.Fatalf("expected 1 ready endpoint, got %d", status.Endpoints)
	}
	if status.LastError != "" {
		t.Fatalf("expected empty last error, got '%s'", status.LastError)
	}
	if status.RetryTimestamp != nil {
		t.Fatalf("expected no retry timestamp, got %v", status.RetryTimestamp)
	}
	if len(status.Conditions) != 1 || status.Conditions[0].Status != metav1.ConditionTrue || status.Conditions[0].Reason != reasonMirrored {
		t.Fatalf("expected a single Mirrored=True condition, got %+v", status.Conditions)
	}
}

// TestMirrorStatusConvergesOnDelete ensures that deleting the source Service
// in the remote cluster removes the mirror status entry so that the status
// converges, while unrelated entries are left untouched.
func TestMirrorStatusConvergesOnDelete(t *testing.T) {
	seed := &v1alpha3.LinkStatus{
		MirrorServices: []v1alpha3.ServiceStatus{
			{
				ControllerName:  serviceMirrorControllerName,
				RemoteRef:       serviceObjectRef("test-service-remote-to-delete", "test-namespace-to-delete"),
				ImportedVersion: "123",
				Endpoints:       1,
				Conditions: []v1alpha3.LinkCondition{
					mirrorStatusCondition(true, reasonMirrored, "", nil),
				},
			},
			{
				ControllerName:  serviceMirrorControllerName,
				RemoteRef:       serviceObjectRef("other-service", "other-namespace"),
				ImportedVersion: "456",
				Endpoints:       2,
				Conditions: []v1alpha3.LinkCondition{
					mirrorStatusCondition(true, reasonMirrored, "", nil),
				},
			},
		},
	}

	localAPI, link := runStatusEnvironment(t, deleteMirrorService, seed)

	// The deleted source Service's status entry must converge away.
	assertNoMirrorStatus(t, link, "test-namespace-to-delete", "test-service-remote-to-delete")

	// Unrelated entries must be preserved.
	other := getMirrorStatus(t, link, "other-namespace", "other-service")
	if other.ImportedVersion != "456" || other.Endpoints != 2 {
		t.Fatalf("unexpected state of the unrelated status entry: %+v", other)
	}

	// The local mirror Service must be deleted.
	_, err := localAPI.Client.CoreV1().Services("test-namespace-to-delete").Get(
		context.Background(), "test-service-remote-to-delete-remote", metav1.GetOptions{},
	)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected mirror service to be deleted, got: %v", err)
	}
}

// TestMirrorStatusSameNameDifferentNamespaces ensures that exported services
// sharing the same name but living in different namespaces are mirrored and
// reported independently, and that deleting one converges only its own
// status and mirror resources.
func TestMirrorStatusSameNameDifferentNamespaces(t *testing.T) {
	ports := []corev1.ServicePort{{Name: "port1", Protocol: "TCP", Port: 555}}
	gatewayPorts := []corev1.EndpointPort{{Name: "port1", Port: 888, Protocol: "TCP"}}

	env := &testEnvironment{
		events: []interface{}{
			&RemoteServiceExported{
				service: remoteService("dup", "ns-a", "100", map[string]string{
					consts.DefaultExportedServiceSelector: "true",
				}, ports),
			},
			&RemoteServiceExported{
				service: remoteService("dup", "ns-b", "200", map[string]string{
					consts.DefaultExportedServiceSelector: "true",
				}, ports),
			},
		},
		remoteResources: []string{
			asYaml(gateway("gateway", "gateway-ns", "1", "192.0.2.127", "gateway", 888, "gateway-identity", defaultProbePort, defaultProbePath, defaultProbePeriod)),
			asYaml(endpoints("dup", "ns-a", nil, "192.0.2.127", "gateway-identity", gatewayPorts)),
			asYaml(endpoints("dup", "ns-b", nil, "192.0.2.127", "gateway-identity", gatewayPorts)),
		},
		localResources: []string{
			asYaml(namespace("ns-a")),
			asYaml(namespace("ns-b")),
		},
		link: v1alpha3.Link{
			Spec: v1alpha3.LinkSpec{
				TargetClusterName:       clusterName,
				TargetClusterDomain:     clusterDomain,
				GatewayIdentity:         "gateway-identity",
				GatewayAddress:          "192.0.2.127",
				GatewayPort:             "888",
				ProbeSpec:               defaultProbeSpec,
				Selector:                defaultSelector,
				RemoteDiscoverySelector: defaultRemoteDiscoverySelector,
			},
		},
	}

	localAPI, link := runStatusEnvironment(t, env, nil)

	if len(link.Status.MirrorServices) != 2 {
		t.Fatalf("expected 2 independent status entries, got %d: %+v", len(link.Status.MirrorServices), link.Status.MirrorServices)
	}
	statusA := getMirrorStatus(t, link, "ns-a", "dup")
	statusB := getMirrorStatus(t, link, "ns-b", "dup")
	if statusA.ImportedVersion != "100" || statusA.Endpoints != 1 {
		t.Fatalf("unexpected ns-a mirror status: %+v", statusA)
	}
	if statusB.ImportedVersion != "200" || statusB.Endpoints != 1 {
		t.Fatalf("unexpected ns-b mirror status: %+v", statusB)
	}
	for _, namespace := range []string{"ns-a", "ns-b"} {
		if _, err := localAPI.Client.CoreV1().Services(namespace).Get(context.Background(), "dup-remote", metav1.GetOptions{}); err != nil {
			t.Fatalf("expected mirror service dup-remote in %s: %v", namespace, err)
		}
	}

	// Delete the source service in ns-a only: its entry and mirror must
	// converge while ns-b stays mirrored.
	limiter := workqueue.DefaultTypedControllerRateLimiter[any]()
	q := workqueue.NewTypedRateLimitingQueue(limiter)
	remoteAPI, err := k8s.NewFakeAPI(env.remoteResources...)
	if err != nil {
		t.Fatal(err)
	}
	linksAPI := k8s.NewNamespacedAPI(nil, nil, localAPI.L5dClient, statusTestNamespace, "local", k8s.Link)
	remoteAPI.Sync(nil)
	linksAPI.Sync(nil)
	watcher := &RemoteClusterServiceWatcher{
		link:            link,
		remoteAPIClient: remoteAPI,
		localAPIClient:  localAPI,
		linksAPIClient:  linksAPI,
		log:             logging.WithFields(logging.Fields{"cluster": clusterName}),
		eventsQueue:     q,
		rateLimiter:     limiter,
		requeueLimit:    0,
	}
	q.Add(&RemoteServiceUnexported{Name: "dup", Namespace: "ns-a"})
	watcher.processNextEvent(context.Background())

	refreshed, err := localAPI.L5dClient.LinkV1alpha3().Links(statusTestNamespace).Get(
		context.Background(), statusTestLinkName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	assertNoMirrorStatus(t, refreshed, "ns-a", "dup")
	getMirrorStatus(t, refreshed, "ns-b", "dup")

	if _, err := localAPI.Client.CoreV1().Services("ns-a").Get(context.Background(), "dup-remote", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected ns-a mirror to be deleted, got: %v", err)
	}
	if _, err := localAPI.Client.CoreV1().Services("ns-b").Get(context.Background(), "dup-remote", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected ns-b mirror to be preserved, got: %v", err)
	}
}

// TestRecordMirrorEventFailure verifies that a reconcile failure records the
// last error and the rate-limited retry time, and that giving up clears the
// retry time while retaining the error for observability.
func TestRecordMirrorEventFailure(t *testing.T) {
	localAPI, err := k8s.NewFakeAPIWithL5dClient()
	if err != nil {
		t.Fatal(err)
	}
	linksAPI := k8s.NewNamespacedAPI(nil, nil, localAPI.L5dClient, statusTestNamespace, "local", k8s.Link)
	localAPI.Sync(nil)
	linksAPI.Sync(nil)

	link := &v1alpha3.Link{
		ObjectMeta: metav1.ObjectMeta{Name: statusTestLinkName, Namespace: statusTestNamespace},
		Spec:       v1alpha3.LinkSpec{TargetClusterName: clusterName},
	}
	_, err = localAPI.L5dClient.LinkV1alpha3().Links(statusTestNamespace).Create(context.Background(), link, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	limiter := workqueue.DefaultTypedControllerRateLimiter[any]()
	q := workqueue.NewTypedRateLimitingQueue(limiter)
	watcher := &RemoteClusterServiceWatcher{
		link:           link,
		localAPIClient: localAPI,
		linksAPIClient: linksAPI,
		log:            logging.WithFields(logging.Fields{"cluster": clusterName}),
		eventsQueue:    q,
		rateLimiter:    limiter,
	}

	ev := &RemoteServiceExported{
		service: remoteService("retry-svc", "ns1", "1", map[string]string{
			consts.DefaultExportedServiceSelector: "true",
		}, nil),
	}
	q.AddRateLimited(ev)

	before := time.Now()
	watcher.recordMirrorEventFailure(ev, RetryableError{[]error{errors.New("boom")}}, true)

	refreshed, err := localAPI.L5dClient.LinkV1alpha3().Links(statusTestNamespace).Get(
		context.Background(), statusTestLinkName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	status := getMirrorStatus(t, refreshed, "ns1", "retry-svc")
	if !strings.Contains(status.LastError, "boom") {
		t.Fatalf("expected last error to contain 'boom', got '%s'", status.LastError)
	}
	if status.RetryTimestamp == nil {
		t.Fatal("expected a retry timestamp to be recorded")
	}
	// metav1.Time truncates to second precision, so compare with a one
	// second slack: the retry must be scheduled at (or after) the failure
	// time.
	if status.RetryTimestamp.Time.Before(before.Add(-time.Second)) {
		t.Fatalf("expected retry timestamp %v to be scheduled around/after the failure time %v", status.RetryTimestamp.Time, before)
	}
	if len(status.Conditions) != 1 || status.Conditions[0].Status != metav1.ConditionFalse || status.Conditions[0].Reason != reasonError {
		t.Fatalf("expected a synthesized Mirrored=False/Error condition, got %+v", status.Conditions)
	}

	// Once retries are exhausted the retry time is cleared but the error is
	// retained.
	watcher.recordMirrorEventFailure(ev, errors.New("still failing"), false)
	refreshed, err = localAPI.L5dClient.LinkV1alpha3().Links(statusTestNamespace).Get(
		context.Background(), statusTestLinkName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	status = getMirrorStatus(t, refreshed, "ns1", "retry-svc")
	if status.RetryTimestamp != nil {
		t.Fatalf("expected retry timestamp to be cleared after giving up, got %v", status.RetryTimestamp)
	}
	if status.LastError != "still failing" {
		t.Fatalf("expected the last error to be retained, got '%s'", status.LastError)
	}
}

func TestRemoteMirrorServiceRef(t *testing.T) {
	exported := remoteService("svc", "ns", "1", nil, nil)
	for _, tt := range []struct {
		event     interface{}
		name      string
		namespace string
		ok        bool
	}{
		{&OnAddCalled{svc: exported}, "svc", "ns", true},
		{&OnUpdateCalled{svc: exported}, "svc", "ns", true},
		{&OnDeleteCalled{svc: exported}, "svc", "ns", true},
		{&RemoteServiceExported{service: exported}, "svc", "ns", true},
		{&RemoteExportedServiceUpdated{remoteUpdate: exported}, "svc", "ns", true},
		{&RemoteServiceUnexported{Name: "svc", Namespace: "ns"}, "svc", "ns", true},
		{&OnAddEndpointsCalled{ep: &corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"}}}, "svc", "ns", true},
		{&OnUpdateEndpointsCalled{ep: &corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"}}}, "svc", "ns", true},
		{&OrphanedServicesGcTriggered{}, "", "", false},
		{&RepairEndpoints{}, "", "", false},
		{&ClusterUnregistered{}, "", "", false},
	} {
		name, namespace, ok := remoteMirrorServiceRef(tt.event)
		if ok != tt.ok || name != tt.name || namespace != tt.namespace {
			t.Fatalf("remoteMirrorServiceRef(%T) = (%s,%s,%t), expected (%s,%s,%t)",
				tt.event, name, namespace, ok, tt.name, tt.namespace, tt.ok)
		}
	}
}
