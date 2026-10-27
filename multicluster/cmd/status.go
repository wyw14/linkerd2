package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/linkerd/linkerd2/cli/table"
	"github.com/linkerd/linkerd2/controller/gen/apis/link/v1alpha3"
	controllerK8s "github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/k8s"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

const (
	destinationServiceName = "linkerd-destination"

	multiclusterControllerComponent = "multicluster-controller"
	serviceMirrorComponent          = "service-mirror"
	destinationComponent            = "destination"

	// perClusterStatusTimeout bounds the status collection of a single remote
	// cluster so that one unreachable cluster cannot block the others.
	perClusterStatusTimeout = 5 * time.Second

	readyValue    = "True"
	notReadyValue = "False"
)

type (
	statusOptions struct {
		clusterName string
		output      string
		wait        time.Duration
	}

	// componentStatusRow describes the health of a single multicluster
	// component: the multicluster controller, the per-link service mirror or
	// the core destination service.
	componentStatusRow struct {
		Component string `json:"component"`
		Cluster   string `json:"cluster,omitempty"`
		Ready     bool   `json:"ready"`
		Detail    string `json:"detail,omitempty"`
	}

	// mirroredServiceStatus is the mirror status of a single remote Service.
	mirroredServiceStatus struct {
		// Cluster is the name of the remote cluster the Service is imported
		// from.
		Cluster string `json:"cluster"`
		// Namespace and Name identify the source Service in the remote
		// cluster.
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		// MirroredName is the local mirror Service name.
		MirroredName string `json:"mirroredName"`
		// Mirrored reports the last state of the Mirrored condition.
		Mirrored bool `json:"mirrored"`
		// Reason is the machine readable condition reason (Mirrored, Error,
		// MissingNamespace, ...).
		Reason string `json:"reason,omitempty"`
		// ImportedVersion is the remote resource version that was mirrored
		// most recently.
		ImportedVersion string `json:"importedVersion,omitempty"`
		// Endpoints is the number of ready endpoint addresses currently
		// exposed by the local mirror Service.
		Endpoints int32 `json:"endpoints"`
		// LastError is the last reconciliation error, empty when healthy.
		LastError string `json:"lastError,omitempty"`
		// RetryTimestamp is the time at which a failed mirror will be
		// retried, empty when healthy.
		RetryTimestamp string `json:"retryTimestamp,omitempty"`
	}

	// clusterStatusError is reported when the status of a single remote
	// cluster cannot be collected. Other clusters are unaffected.
	clusterStatusError struct {
		Cluster string `json:"cluster"`
		Error   string `json:"error"`
	}

	multiclusterStatusReport struct {
		Components       []componentStatusRow    `json:"components"`
		MirroredServices []mirroredServiceStatus `json:"mirroredServices"`
		Errors           []clusterStatusError    `json:"errors,omitempty"`
	}

	clusterStatusResult struct {
		services []mirroredServiceStatus
	}

	// clusterStatusFetcher collects the mirror status of a single remote
	// cluster. It is a function type so that failures and timeouts can be
	// exercised in tests.
	clusterStatusFetcher func(ctx context.Context, link *v1alpha3.Link) (*clusterStatusResult, error)
)

func newStatusCommand() *cobra.Command {
	opts := statusOptions{
		wait: 30 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display the mirror status of services imported from target clusters",
		Long: `Display the mirror status of services imported from target clusters.

For every target cluster the command reports the health of the multicluster
controller, of the per-link service mirror and of the core destination
service, together with the mirror status of every imported Service: its
imported remote version, the number of ready mirror endpoints, the last
reconciliation error and the time at which the mirror will be retried.

The status of each cluster is collected independently; an unreachable remote
cluster does not block the status of the other clusters.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			if err != nil {
				return err
			}

			multiclusterNs, err := k8sAPI.GetNamespaceWithExtensionLabel(cmd.Context(), MulticlusterExtensionName)
			if err != nil {
				return fmt.Errorf("make sure the linkerd-multicluster extension is installed, using 'linkerd multicluster install' (%w)", err)
			}

			config, err := k8s.GetConfig(kubeconfigPath, kubeContext)
			if err != nil {
				return err
			}
			l5dAPI, err := controllerK8s.NewL5DCRDClient(config)
			if err != nil {
				return fmt.Errorf("failed to initialize Linkerd CRD client: %w", err)
			}

			links, err := l5dAPI.LinkV1alpha3().Links(multiclusterNs.Name).List(cmd.Context(), metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to list Links in namespace %s: %w", multiclusterNs.Name, err)
			}
			var filtered []*v1alpha3.Link
			for i := range links.Items {
				link := &links.Items[i]
				if opts.clusterName == "" || link.Spec.TargetClusterName == opts.clusterName {
					filtered = append(filtered, link)
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), opts.wait)
			defer cancel()

			checker := newStatusChecker(k8sAPI)
			services, fetchErrs := collectClusterStatuses(ctx, filtered, checker.fetchClusterStatus, perClusterStatusTimeout)
			components := checker.componentStatus(ctx, multiclusterNs.Name, controlPlaneNamespace, filtered)

			// Per-cluster collection errors are reported but do not fail the
			// command: the remaining clusters are still displayed.
			for _, fetchErr := range fetchErrs {
				fmt.Fprintf(stderr, "failed to collect mirror status for cluster %s: %s\n", fetchErr.Cluster, fetchErr.Error)
			}

			report := multiclusterStatusReport{
				Components:       components,
				MirroredServices: services,
				Errors:           fetchErrs,
			}

			switch opts.output {
			case "json":
				out, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				fmt.Printf("%s\n", out)
			default:
				renderComponents(components, stdout)
				fmt.Fprintln(stdout)
				renderMirroredServices(services, stdout)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.clusterName, "cluster-name", "", "only display the status of the target cluster")
	cmd.Flags().DurationVarP(&opts.wait, "wait", "w", opts.wait, "time allowed to collect the status of all clusters")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "output format; one of: table, json")

	return cmd
}

// statusChecker collects mirror status information from the local cluster.
type statusChecker struct {
	k8sAPI kubernetes.Interface
}

func newStatusChecker(k8sAPI kubernetes.Interface) *statusChecker {
	return &statusChecker{k8sAPI: k8sAPI}
}

// fetchClusterStatus collects the mirror status of every Service imported from
// the cluster targeted by link. It joins the Link status entries written by
// the service mirror with the local mirror Service and Endpoints resources.
func (c *statusChecker) fetchClusterStatus(ctx context.Context, link *v1alpha3.Link) (*clusterStatusResult, error) {
	cluster := link.Spec.TargetClusterName

	mirrorSelector := labels.SelectorFromSet(labels.Set{
		k8s.MirroredResourceLabel:  "true",
		k8s.RemoteClusterNameLabel: cluster,
	})
	services, err := c.k8sAPI.CoreV1().Services(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: mirrorSelector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list mirror services for cluster %s: %w", cluster, err)
	}

	type localMirror struct {
		version   string
		endpoints int32
	}
	mirrors := make(map[string]*localMirror)
	for i := range services.Items {
		svc := &services.Items[i]
		// Headless mirrors create an auxiliary Service per backing pod;
		// those are not imported Services and must not be reported.
		if _, ok := svc.Labels[k8s.MirroredHeadlessSvcNameLabel]; ok {
			continue
		}
		remoteName := strings.TrimSuffix(svc.Name, "-"+cluster)
		mirrors[serviceRefKey(svc.Namespace, remoteName)] = &localMirror{
			version:   svc.Annotations[k8s.RemoteResourceVersionAnnotation],
			endpoints: c.readyEndpoints(ctx, svc.Namespace, svc.Name),
		}
	}

	refs := make(map[string]struct{})
	for key := range mirrors {
		refs[key] = struct{}{}
	}
	statuses := make(map[string]v1alpha3.ServiceStatus)
	for _, status := range link.Status.MirrorServices {
		key := serviceRefKey(status.RemoteRef.Namespace, status.RemoteRef.Name)
		refs[key] = struct{}{}
		statuses[key] = status
	}

	result := &clusterStatusResult{}
	for key := range refs {
		namespace, name := parseServiceRefKey(key)
		row := mirroredServiceStatus{
			Cluster:      cluster,
			Namespace:    namespace,
			Name:         name,
			MirroredName: fmt.Sprintf("%s-%s", name, cluster),
		}
		if mirror := mirrors[key]; mirror != nil {
			row.ImportedVersion = mirror.version
			row.Endpoints = mirror.endpoints
			row.Mirrored = true
		}
		if status, ok := statuses[key]; ok {
			applyServiceStatus(&row, status)
		}
		result.services = append(result.services, row)
	}

	sort.Slice(result.services, func(i, j int) bool {
		return mirroredServiceKey(result.services[i]) < mirroredServiceKey(result.services[j])
	})
	return result, nil
}

// applyServiceStatus enriches a status row with the information recorded by
// the service mirror in the Link status.
func applyServiceStatus(row *mirroredServiceStatus, status v1alpha3.ServiceStatus) {
	if status.ImportedVersion != "" {
		row.ImportedVersion = status.ImportedVersion
	}
	if status.Endpoints > 0 {
		row.Endpoints = status.Endpoints
	}
	row.LastError = status.LastError
	if status.RetryTimestamp != nil {
		row.RetryTimestamp = status.RetryTimestamp.UTC().Format(time.RFC3339)
	}
	for _, condition := range status.Conditions {
		if condition.Type != "Mirrored" {
			continue
		}
		row.Mirrored = condition.Status == metav1.ConditionTrue
		row.Reason = condition.Reason
		if !row.Mirrored && row.LastError == "" {
			row.LastError = condition.Message
		}
		if condition.LocalRef != nil {
			row.MirroredName = condition.LocalRef.Name
		}
	}
}

// readyEndpoints returns the number of ready addresses exposed by the named
// Endpoints object. Missing or empty endpoints report zero.
func (c *statusChecker) readyEndpoints(ctx context.Context, namespace, name string) int32 {
	endpoints, err := c.k8sAPI.CoreV1().Endpoints(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			log.Debugf("failed to get mirror endpoints %s/%s: %s", namespace, name, err)
		}
		return 0
	}
	var count int32
	for _, subset := range endpoints.Subsets {
		count += int32(len(subset.Addresses))
	}
	return count
}

// componentStatus reports the health of the multicluster controller and
// service mirror pods (grouped per target cluster) together with the core
// destination service which resolves mirrored services.
func (c *statusChecker) componentStatus(ctx context.Context, multiclusterNamespace, controlPlaneNamespace string, links []*v1alpha3.Link) []componentStatusRow {
	rows := []componentStatusRow{}

	// Seed one row per component per linked cluster so that missing
	// controller/service-mirror pods are still reported.
	clusters := make(map[string]struct{})
	for _, link := range links {
		clusters[link.Spec.TargetClusterName] = struct{}{}
		rows = append(rows,
			componentStatusRow{Component: multiclusterControllerComponent, Cluster: link.Spec.TargetClusterName, Ready: false, Detail: "no controller pods found"},
			componentStatusRow{Component: serviceMirrorComponent, Cluster: link.Spec.TargetClusterName, Ready: false, Detail: "no service mirror pods found"},
		)
	}

	pods, err := c.k8sAPI.CoreV1().Pods(multiclusterNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "component in (linkerd-service-mirror, controller)",
	})
	if err != nil {
		log.Debugf("failed to list multicluster pods: %s", err)
	} else {
		for i := range pods.Items {
			pod := &pods.Items[i]
			component := pod.Labels["component"]
			switch component {
			case "controller":
				component = multiclusterControllerComponent
			case "linkerd-service-mirror":
				component = serviceMirrorComponent
			default:
				continue
			}
			cluster := pod.Labels[k8s.RemoteClusterNameLabel]
			if cluster == "" {
				// Pods without a cluster label cannot be attributed to a
				// Link, skip them.
				continue
			}
			if _, ok := clusters[cluster]; !ok {
				// The pod belongs to a cluster that was filtered out.
				continue
			}
			upsertComponentRow(&rows, componentStatusRow{
				Component: component,
				Cluster:   cluster,
				Ready:     podReady(pod),
				Detail:    podStatusDetail(pod),
			})
		}
	}

	// The destination service is shared by every cluster.
	destinationReady := false
	destinationDetail := "destination service not found"
	service, err := c.k8sAPI.CoreV1().Services(controlPlaneNamespace).Get(ctx, destinationServiceName, metav1.GetOptions{})
	if err == nil {
		endpoints := c.readyEndpoints(ctx, service.Namespace, service.Name)
		if endpoints > 0 {
			destinationReady = true
			destinationDetail = fmt.Sprintf("%d ready endpoint(s)", endpoints)
		} else {
			destinationDetail = "destination service has no ready endpoints"
		}
	} else if !apierrors.IsNotFound(err) {
		destinationDetail = fmt.Sprintf("failed to get destination service: %s", err)
	}
	rows = append(rows, componentStatusRow{
		Component: destinationComponent,
		Ready:     destinationReady,
		Detail:    destinationDetail,
	})

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Component != rows[j].Component {
			return rows[i].Component < rows[j].Component
		}
		return rows[i].Cluster < rows[j].Cluster
	})
	return rows
}

func upsertComponentRow(rows *[]componentStatusRow, row componentStatusRow) {
	for i := range *rows {
		if (*rows)[i].Component == row.Component && (*rows)[i].Cluster == row.Cluster {
			// A ready pod wins over a non-ready one.
			if row.Ready {
				(*rows)[i] = row
			}
			return
		}
	}
	*rows = append(*rows, row)
}

func podReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func podStatusDetail(pod *corev1.Pod) string {
	if podReady(pod) {
		return "running"
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionFalse {
			return fmt.Sprintf("not ready: %s", condition.Reason)
		}
	}
	return fmt.Sprintf("phase %s", pod.Status.Phase)
}

// collectClusterStatuses fans out the status collection across the links,
// bounding every per-cluster call with perClusterTimeout. A slow or failing
// fetch for one cluster cannot block the other clusters: results are written
// to a buffered channel and failures are returned as standalone errors.
func collectClusterStatuses(
	ctx context.Context,
	links []*v1alpha3.Link,
	fetch clusterStatusFetcher,
	perClusterTimeout time.Duration,
) ([]mirroredServiceStatus, []clusterStatusError) {
	type fetchResult struct {
		cluster string
		result  *clusterStatusResult
		err     error
	}

	results := make(chan fetchResult, len(links))
	var wg sync.WaitGroup
	for _, link := range links {
		wg.Add(1)
		go func(link *v1alpha3.Link) {
			defer wg.Done()
			clusterCtx, cancel := context.WithTimeout(ctx, perClusterTimeout)
			defer cancel()
			result, err := fetch(clusterCtx, link)
			results <- fetchResult{
				cluster: link.Spec.TargetClusterName,
				result:  result,
				err:     err,
			}
		}(link)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var services []mirroredServiceStatus
	var errs []clusterStatusError
	for result := range results {
		if result.err != nil {
			errs = append(errs, clusterStatusError{
				Cluster: result.cluster,
				Error:   result.err.Error(),
			})
			continue
		}
		services = append(services, result.result.services...)
	}

	sort.Slice(services, func(i, j int) bool {
		return mirroredServiceKey(services[i]) < mirroredServiceKey(services[j])
	})
	sort.Slice(errs, func(i, j int) bool {
		return errs[i].Cluster < errs[j].Cluster
	})
	return services, errs
}

func serviceRefKey(namespace, name string) string {
	return namespace + "/" + name
}

func parseServiceRefKey(key string) (namespace, name string) {
	namespace, name, _ = strings.Cut(key, "/")
	return namespace, name
}

func mirroredServiceKey(row mirroredServiceStatus) string {
	return fmt.Sprintf("%s/%s/%s", row.Cluster, row.Namespace, row.Name)
}

func renderComponents(rows []componentStatusRow, w io.Writer) {
	t := table.NewTable([]table.Column{
		{Header: "COMPONENT", Width: 24, Flexible: true, LeftAlign: true},
		{Header: "CLUSTER", Width: 10, Flexible: true, LeftAlign: true},
		{Header: "STATUS", Width: 6},
		{Header: "DETAIL", Width: 10, Flexible: true, LeftAlign: true},
	}, []table.Row{})
	for _, row := range rows {
		ready := notReadyValue
		if row.Ready {
			ready = readyValue
		}
		t.Data = append(t.Data, table.Row{row.Component, row.Cluster, ready, row.Detail})
	}
	t.Render(w)
}

func renderMirroredServices(rows []mirroredServiceStatus, w io.Writer) {
	t := table.NewTable([]table.Column{
		{Header: "CLUSTER", Width: 8, Flexible: true, LeftAlign: true},
		{Header: "NAMESPACE", Width: 10, Flexible: true, LeftAlign: true},
		{Header: "SERVICE", Width: 10, Flexible: true, LeftAlign: true},
		{Header: "VERSION", Width: 8},
		{Header: "ENDPOINTS", Width: 9},
		{Header: "MIRRORED", Width: 8},
		{Header: "LAST_ERROR", Width: 12, Flexible: true, LeftAlign: true},
		{Header: "RETRY", Width: 22, Flexible: true, LeftAlign: true},
	}, []table.Row{})
	for _, row := range rows {
		mirrored := notReadyValue
		if row.Mirrored {
			mirrored = readyValue
		}
		t.Data = append(t.Data, table.Row{
			row.Cluster,
			row.Namespace,
			row.Name,
			row.ImportedVersion,
			fmt.Sprint(row.Endpoints),
			mirrored,
			row.LastError,
			row.RetryTimestamp,
		})
	}
	t.Render(w)
}
