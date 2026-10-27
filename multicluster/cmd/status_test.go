package cmd

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/linkerd/linkerd2/controller/gen/apis/link/v1alpha3"
	l5dfake "github.com/linkerd/linkerd2/controller/gen/client/clientset/versioned/fake"
	"github.com/linkerd/linkerd2/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testMulticlusterNamespace = "linkerd-multicluster"
	testControlPlaneNamespace = "linkerd"
)

func mirrorService(name, namespace, cluster, version string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				k8s.MirroredResourceLabel:  "true",
				k8s.RemoteClusterNameLabel: cluster,
			},
			Annotations: map[string]string{
				k8s.RemoteResourceVersionAnnotation: version,
			},
		},
	}
}

// headlessAuxiliaryService builds the per-pod auxiliary Service created for a
// mirrored headless Service.
func headlessAuxiliaryService(name, namespace, rootMirror string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				k8s.MirroredResourceLabel:        "true",
				k8s.RemoteClusterNameLabel:       "east",
				k8s.MirroredHeadlessSvcNameLabel: rootMirror,
			},
		},
	}
}

func mirrorEndpoints(name, namespace string, ready, notReady []string) *corev1.Endpoints {
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	var addresses []corev1.EndpointAddress
	for _, ip := range ready {
		addresses = append(addresses, corev1.EndpointAddress{IP: ip})
	}
	var notReadyAddresses []corev1.EndpointAddress
	for _, ip := range notReady {
		notReadyAddresses = append(notReadyAddresses, corev1.EndpointAddress{IP: ip})
	}
	if len(addresses) > 0 || len(notReadyAddresses) > 0 {
		ep.Subsets = []corev1.EndpointSubset{{
			Addresses:         addresses,
			NotReadyAddresses: notReadyAddresses,
		}}
	}
	return ep
}

func mcPod(name, component, cluster string, phase corev1.PodPhase, ready bool, reason string) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testMulticlusterNamespace,
			Labels: map[string]string{
				"component":                component,
				k8s.RemoteClusterNameLabel: cluster,
			},
		},
		Status: corev1.PodStatus{
			Phase: phase,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: status,
				Reason: reason,
			}},
		},
	}
}

func newStatusTestClients(t *testing.T) (*fake.Clientset, *l5dfake.Clientset, []*v1alpha3.Link) {
	t.Helper()

	retryTime := metav1.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	eastLink := &v1alpha3.Link{
		ObjectMeta: metav1.ObjectMeta{Name: "east", Namespace: testMulticlusterNamespace},
		Spec:       v1alpha3.LinkSpec{TargetClusterName: "east"},
		Status: v1alpha3.LinkStatus{
			MirrorServices: []v1alpha3.ServiceStatus{
				{
					ControllerName:  "linkerd.io/service-mirror",
					RemoteRef:       serviceRef("ns1", "svc1"),
					ImportedVersion: "555",
					Endpoints:       2,
					Conditions: []v1alpha3.LinkCondition{{
						Type:   "Mirrored",
						Status: metav1.ConditionTrue,
						Reason: "Mirrored",
					}},
				},
				{
					ControllerName:  "linkerd.io/service-mirror",
					RemoteRef:       serviceRef("ns1", "svc2"),
					ImportedVersion: "777",
					LastError:       "failed to update mirror endpoints: conflict",
					RetryTimestamp:  &retryTime,
					Conditions: []v1alpha3.LinkCondition{{
						Type:    "Mirrored",
						Status:  metav1.ConditionFalse,
						Reason:  "Error",
						Message: "failed to update mirror endpoints: conflict",
					}},
				},
				{
					ControllerName: "linkerd.io/service-mirror",
					RemoteRef:      serviceRef("ns3", "ghost"),
					LastError:      "missing namespace",
					Conditions: []v1alpha3.LinkCondition{{
						Type:    "Mirrored",
						Status:  metav1.ConditionFalse,
						Reason:  "MissingNamespace",
						Message: "missing namespace",
					}},
				},
			},
		},
	}
	westLink := &v1alpha3.Link{
		ObjectMeta: metav1.ObjectMeta{Name: "west", Namespace: testMulticlusterNamespace},
		Spec:       v1alpha3.LinkSpec{TargetClusterName: "west"},
	}
	northLink := &v1alpha3.Link{
		ObjectMeta: metav1.ObjectMeta{Name: "north", Namespace: testMulticlusterNamespace},
		Spec:       v1alpha3.LinkSpec{TargetClusterName: "north"},
	}

	coreClient := fake.NewSimpleClientset(
		// Multicluster controller / service mirror pods.
		mcPod("controller-east", "controller", "east", corev1.PodRunning, true, ""),
		mcPod("service-mirror-west", "linkerd-service-mirror", "west", corev1.PodRunning, false, "ContainersNotReady"),
		// Local mirror services.
		mirrorService("svc1-east", "ns1", "east", "555"),
		mirrorService("svc2-east", "ns1", "east", "777"),
		mirrorService("svc9-west", "ns2", "west", "9"),
		// Headless mirror auxiliary service for a backing pod; it must not be
		// reported as an imported Service.
		headlessAuxiliaryService("pod-0-east", "ns1", "headless-east"),
		// Local mirror endpoints. svc2 has no endpoints, the west mirror
		// exposes one ready and one not-ready address.
		mirrorEndpoints("svc1-east", "ns1", []string{"10.0.0.1", "10.0.0.2"}, nil),
		mirrorEndpoints("svc9-west", "ns2", []string{"10.1.0.1"}, []string{"10.1.0.2"}),
		// Core destination service with one endpoint.
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: destinationServiceName, Namespace: testControlPlaneNamespace}},
		mirrorEndpoints(destinationServiceName, testControlPlaneNamespace, []string{"10.255.0.1"}, nil),
	)

	links := []*v1alpha3.Link{eastLink, westLink, northLink}
	l5dClient := l5dfake.NewSimpleClientset()
	for _, link := range links {
		if _, err := l5dClient.LinkV1alpha3().Links(testMulticlusterNamespace).Create(
			context.Background(), link, metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
	}
	return coreClient, l5dClient, links
}

func serviceRef(namespace, name string) v1alpha3.ObjectRef {
	return v1alpha3.ObjectRef{
		Group:     corev1.GroupName,
		Kind:      "Service",
		Name:      name,
		Namespace: namespace,
	}
}

func findRow(rows []mirroredServiceStatus, cluster, namespace, name string) mirroredServiceStatus {
	for _, row := range rows {
		if row.Cluster == cluster && row.Namespace == namespace && row.Name == name {
			return row
		}
	}
	return mirroredServiceStatus{}
}

// TestFetchClusterStatus verifies that the local mirror resources and the
// Link status entries are joined into per-service rows reporting the imported
// version, endpoint count, last error and retry time.
func TestFetchClusterStatus(t *testing.T) {
	coreClient, _, links := newStatusTestClients(t)
	checker := newStatusChecker(coreClient)

	east := links[0]
	result, err := checker.fetchClusterStatus(context.Background(), east)
	if err != nil {
		t.Fatalf("unexpected error fetching east status: %s", err)
	}
	if len(result.services) != 3 {
		t.Fatalf("expected 3 rows for east (including the ghost entry), got %d: %+v", len(result.services), result.services)
	}
	for _, row := range result.services {
		if row.Name == "pod-0" {
			t.Fatalf("headless auxiliary service must not be reported as an imported Service: %+v", row)
		}
	}

	svc1 := findRow(result.services, "east", "ns1", "svc1")
	if svc1.ImportedVersion != "555" || svc1.Endpoints != 2 || !svc1.Mirrored || svc1.LastError != "" || svc1.RetryTimestamp != "" {
		t.Fatalf("unexpected healthy row: %+v", svc1)
	}

	svc2 := findRow(result.services, "east", "ns1", "svc2")
	if svc2.ImportedVersion != "777" {
		t.Fatalf("expected imported version 777, got '%s'", svc2.ImportedVersion)
	}
	if svc2.Endpoints != 0 {
		t.Fatalf("expected 0 endpoints for svc2, got %d", svc2.Endpoints)
	}
	if svc2.Mirrored {
		t.Fatalf("expected svc2 to report a failed mirror state")
	}
	if !strings.Contains(svc2.LastError, "conflict") {
		t.Fatalf("expected the last error to be reported, got '%s'", svc2.LastError)
	}
	if svc2.RetryTimestamp != "2026-01-02T03:04:05Z" {
		t.Fatalf("unexpected retry timestamp: '%s'", svc2.RetryTimestamp)
	}

	ghost := findRow(result.services, "east", "ns3", "ghost")
	if ghost.Mirrored || ghost.Endpoints != 0 || ghost.ImportedVersion != "" || ghost.MirroredName == "" {
		t.Fatalf("expected a ghost row with no local mirror, got: %+v", ghost)
	}
	if ghost.LastError != "missing namespace" {
		t.Fatalf("expected the ghost last error to be reported, got '%s'", ghost.LastError)
	}

	// West has no status entries: the row is derived from the local mirror
	// resources, only ready addresses are counted.
	west := links[1]
	westResult, err := checker.fetchClusterStatus(context.Background(), west)
	if err != nil {
		t.Fatalf("unexpected error fetching west status: %s", err)
	}
	svc9 := findRow(westResult.services, "west", "ns2", "svc9")
	if svc9.ImportedVersion != "9" || svc9.Endpoints != 1 || !svc9.Mirrored {
		t.Fatalf("unexpected west row: %+v", svc9)
	}

	// North has no mirrors: the fetch is successful and returns no rows.
	north := links[2]
	northResult, err := checker.fetchClusterStatus(context.Background(), north)
	if err != nil {
		t.Fatalf("unreachable cluster without mirrors should not error, got: %s", err)
	}
	if len(northResult.services) != 0 {
		t.Fatalf("expected no rows for north, got %+v", northResult.services)
	}
}

// TestComponentStatus verifies the multicluster controller, service mirror
// and destination service health reporting.
func TestComponentStatus(t *testing.T) {
	coreClient, _, links := newStatusTestClients(t)
	checker := newStatusChecker(coreClient)

	rows := checker.componentStatus(context.Background(), testMulticlusterNamespace, testControlPlaneNamespace, links)

	find := func(component, cluster string) componentStatusRow {
		for _, row := range rows {
			if row.Component == component && row.Cluster == cluster {
				return row
			}
		}
		t.Fatalf("missing component row %s/%s: %+v", component, cluster, rows)
		return componentStatusRow{}
	}

	if eastController := find(multiclusterControllerComponent, "east"); !eastController.Ready {
		t.Fatalf("expected east controller to be ready: %+v", eastController)
	}
	if westMirror := find(serviceMirrorComponent, "west"); westMirror.Ready {
		t.Fatalf("expected west service mirror to be not ready: %+v", westMirror)
	}
	if northController := find(multiclusterControllerComponent, "north"); northController.Ready {
		t.Fatalf("expected north controller (no pods) to be not ready: %+v", northController)
	}

	var destination componentStatusRow
	for _, row := range rows {
		if row.Component == destinationComponent {
			destination = row
		}
	}
	if !destination.Ready || !strings.Contains(destination.Detail, "1 ready endpoint") {
		t.Fatalf("unexpected destination status: %+v", destination)
	}
}

// TestCollectClusterStatusesIsolation ensures that a failed or hanging fetch
// for one remote cluster does not block the collection of the others.
func TestCollectClusterStatusesIsolation(t *testing.T) {
	links := []*v1alpha3.Link{
		{Spec: v1alpha3.LinkSpec{TargetClusterName: "east"}},
		{Spec: v1alpha3.LinkSpec{TargetClusterName: "south"}},
		{Spec: v1alpha3.LinkSpec{TargetClusterName: "north"}},
	}

	started := time.Now()
	// The north fetch hangs until its per-cluster context expires,
	// simulating an unreachable remote.
	fetcher := func(ctx context.Context, link *v1alpha3.Link) (*clusterStatusResult, error) {
		switch link.Spec.TargetClusterName {
		case "east":
			return &clusterStatusResult{services: []mirroredServiceStatus{
				{Cluster: "east", Namespace: "ns1", Name: "svc", Mirrored: true},
			}}, nil
		case "south":
			return nil, context.DeadlineExceeded
		case "north":
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &clusterStatusResult{}, nil
	}

	services, errs := collectClusterStatuses(context.Background(), links, fetcher, 100*time.Millisecond)
	elapsed := time.Since(started)

	if elapsed > 3*time.Second {
		t.Fatalf("collection was blocked by the unreachable cluster for %s", elapsed)
	}
	if len(services) != 1 || services[0].Cluster != "east" {
		t.Fatalf("expected only the east rows, got %+v", services)
	}
	if len(errs) != 2 {
		t.Fatalf("expected 2 per-cluster errors, got %+v", errs)
	}
	errorClusters := map[string]bool{}
	for _, fetchErr := range errs {
		errorClusters[fetchErr.Cluster] = true
	}
	if !errorClusters["south"] || !errorClusters["north"] {
		t.Fatalf("expected errors for south and north, got %+v", errs)
	}
}

// TestRenderStatus verifies the table rendering surfaces every reported
// column.
func TestRenderStatus(t *testing.T) {
	coreClient, _, links := newStatusTestClients(t)
	checker := newStatusChecker(coreClient)
	result, err := checker.fetchClusterStatus(context.Background(), links[0])
	if err != nil {
		t.Fatal(err)
	}
	components := checker.componentStatus(context.Background(), testMulticlusterNamespace, testControlPlaneNamespace, links)

	var buf bytes.Buffer
	renderComponents(components, &buf)
	fmt.Fprintln(&buf)
	renderMirroredServices(result.services, &buf)
	out := buf.String()

	for _, expected := range []string{
		"COMPONENT",
		"multicluster-controller",
		"service-mirror",
		"destination",
		"CLUSTER",
		"NAMESPACE",
		"SERVICE",
		"VERSION",
		"ENDPOINTS",
		"LAST_ERROR",
		"RETRY",
		"svc1",
		"svc2",
		"ghost",
		"conflict",
	} {
		if !strings.Contains(out, expected) {
			t.Fatalf("expected rendered status to contain %q, got:\n%s", expected, out)
		}
	}
}
