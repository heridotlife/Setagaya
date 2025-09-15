package scheduler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	apiv1 "k8s.io/api/core/v1"

	"github.com/hveda/Setagaya/setagaya/config"
	model "github.com/hveda/Setagaya/setagaya/model"
	smodel "github.com/hveda/Setagaya/setagaya/scheduler/model"

	"google.golang.org/api/option"
	runv1 "google.golang.org/api/run/v1"
)

type CloudRun struct {
	rs          *runv1.APIService
	projectID   string
	nsProjectID string
	region      string

	// cloud run admin api has quota. This queue is to protect we don't hit the quota
	// If we hit the quota, we cannot do any operations
	throttlingQueue chan *cloudRunRequest
	httpClient      *http.Client
}

func NewCloudRun(cfg *config.ClusterConfig) *CloudRun {
	ctx := context.Background()
	//opts := option.ClientOption{}
	rs, err := runv1.NewService(ctx, option.WithEndpoint(cfg.APIEndpoint))
	if err != nil {
		log.Fatal(err)
	}
	projectID := cfg.Project
	nsProjectID := fmt.Sprintf("namespaces/%s", projectID)
	queue := make(chan *cloudRunRequest, 1000)

	cr := &CloudRun{rs: rs,
		projectID:       projectID,
		nsProjectID:     nsProjectID,
		throttlingQueue: queue,
		region:          cfg.Region}
	cr.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	go cr.startWriteRequestWorker()
	return cr
}

func (cr *CloudRun) MakeName(projectID, collectionID, planID int64, engineID int) string {
	return fmt.Sprintf("engine-%d-%d-%d-%d", projectID, collectionID, planID, engineID)
}

func (cr *CloudRun) makeLabels(projectID, collectionID, planID int64, engineID int) map[string]string {
	m := make(map[string]string)
	fm := strconv.FormatInt
	m["project"] = fm(projectID, 10)
	m["collection"] = fm(collectionID, 10)
	m["plan"] = fm(planID, 10)
	m["engine"] = fm(int64(engineID), 10)
	return m
}

func (cr *CloudRun) makeService(projectID, collectionID, planID int64, engineID int, ec *config.ExecutorContainer) *runv1.Service {
	m := cr.makeLabels(projectID, collectionID, planID, engineID)
	requests := map[string]string{
		"cpu":    ec.CPU,
		"memory": ec.Mem,
	}
	return &runv1.Service{
		ApiVersion: "serving.knative.dev/v1",
		Kind:       "Service",
		Metadata: &runv1.ObjectMeta{
			Name:      cr.MakeName(projectID, collectionID, planID, engineID),
			Namespace: cr.projectID,
			Labels:    m,
			Annotations: map[string]string{
				"run.googleapis.com/launch-stage": "BETA",
			},
		},
		Spec: &runv1.ServiceSpec{
			Template: &runv1.RevisionTemplate{
				Metadata: &runv1.ObjectMeta{
					Annotations: map[string]string{
						"autoscaling.knative.dev/maxScale": "1",
						"autoscaling.knative.dev/minScale": "1",
					},
				},
				Spec: &runv1.RevisionSpec{
					Containers: []*runv1.Container{
						{
							Image: ec.Image,
							Ports: []*runv1.ContainerPort{
								{
									ContainerPort: 8080,
								},
							},
							Resources: &runv1.ResourceRequirements{
								Requests: requests,
								Limits:   requests,
							},
						},
					},
				},
			},
		},
	}
}

func (cr *CloudRun) startWriteRequestWorker() {
	counter := 0
	quota := 150
	for item := range cr.throttlingQueue {
		if counter >= quota {
			time.Sleep(1 * time.Minute)
			counter = 0
		}
		switch item.method {
		case "delete":
			if err := cr.deleteService(item.serviceID); err != nil {
				log.Printf("Error deleting service %s: %v", item.serviceID, err)
			}
			counter += 1
		case "create":
			if err := cr.sendCreateServiceReq(item.projectID, item.collectionID, item.planID, item.engineID, item.executorConfig); err != nil {
				log.Print(err)
			}
			// For each create request, we actually have two operations against the api.
			counter += 2
		}
	}
}

type cloudRunRequest struct {
	method         string
	projectID      int64
	collectionID   int64
	planID         int64
	engineID       int
	serviceID      string
	executorConfig *config.ExecutorContainer
}

func (cr *CloudRun) sendCreateServiceReq(projectID, collectionID, planID int64, engineID int, executorConfig *config.ExecutorContainer) error {
	svc := cr.makeService(projectID, collectionID, planID, engineID, executorConfig)
	_, err := cr.rs.Namespaces.Services.Create(cr.nsProjectID, svc).Do()
	if err != nil {
		return err
	}
	// This is required by cloud run as we need to allow our engines to be triggered by all users
	// https://cloud.google.com/run/docs/reference/rest/v1/projects.locations.services/setIamPolicy
	policy := &runv1.Policy{
		Bindings: []*runv1.Binding{
			{
				Members: []string{"allUsers"},
				Role:    "roles/run.invoker",
			},
		},
	}
	name := fmt.Sprintf("projects/%s/locations/%s/services/%s", cr.projectID, cr.region, svc.Metadata.Name)
	iamRequest := &runv1.SetIamPolicyRequest{
		Policy: policy,
	}
	_, err = cr.rs.Projects.Locations.Services.SetIamPolicy(name, iamRequest).Do()
	if err != nil {
		return err
	}
	return nil
}

func (cr *CloudRun) DeployEngine(projectID, collectionID, planID int64, engineID int, containerConfig *config.ExecutorContainer) error {
	item := &cloudRunRequest{
		method:         "create",
		projectID:      projectID,
		collectionID:   collectionID,
		planID:         planID,
		engineID:       engineID,
		executorConfig: containerConfig,
	}
	cr.throttlingQueue <- item
	return nil
}

func (cr *CloudRun) DeployPlan(projectID, collectionID, planID int64, replicas int, containerConfig *config.ExecutorContainer) error {
	return nil
}

func (cr *CloudRun) deleteService(serviceID string) error {
	name := fmt.Sprintf("%s/services/%s", cr.nsProjectID, serviceID)
	if _, err := cr.rs.Namespaces.Services.Delete(name).Do(); err != nil {
		log.Print(err)
		return err
	}
	return nil
}

func (cr *CloudRun) PurgeCollection(collectionID int64) error {
	items, err := cr.getEnginesByCollection(collectionID)
	if err != nil {
		return err
	}
	for _, item := range items {
		cr.throttlingQueue <- &cloudRunRequest{
			method:    "delete",
			serviceID: item.Metadata.Name,
		}
	}
	return nil
}

func (cr *CloudRun) getEnginesByCollection(collectionID int64) ([]*runv1.Service, error) {
	label := makeCollectionLabel(collectionID)
	resp, err := cr.rs.Namespaces.Services.List(cr.nsProjectID).LabelSelector(label).Do()
	if err != nil {
		return []*runv1.Service{}, err
	}
	return resp.Items, nil
}

func (cr *CloudRun) getEnginesByCollectionPlan(collectionID, planID int64) ([]*runv1.Service, error) {
	label := fmt.Sprintf("collection=%d, plan=%d", collectionID, planID)
	resp, err := cr.rs.Namespaces.Services.List(cr.nsProjectID).LabelSelector(label).Do()
	if err != nil {
		return []*runv1.Service{}, err
	}
	return resp.Items, nil
}

func (cr *CloudRun) CollectionStatus(projectID, collectionID int64, eps []*model.ExecutionPlan) (*smodel.CollectionStatus, error) {
	items, err := cr.getEnginesByCollection(collectionID)
	if err != nil {
		return nil, err
	}
	cs := &smodel.CollectionStatus{}
	planStatuses := make(map[int64]*smodel.PlanStatus)

	// The reason we need this is we want to show users the progress of deployment
	// Usually the engines deployment is quick but network access might be slow.
	// So users should be able to see their engines deployed and later become reachable
	planReachable := make(map[int64]int)
	for _, ep := range eps {
		ps := &smodel.PlanStatus{
			PlanID:  ep.PlanID,
			Engines: ep.Engines,
		}
		planStatuses[ep.PlanID] = ps
	}
	for _, item := range items {
		planID, err := strconv.Atoi(item.Metadata.Labels["plan"])
		if err != nil {
			log.Error(err)
		}
		pid := int64(planID)
		ps, ok := planStatuses[pid]
		if !ok {
			log.Error("Could not find running pod in ExecutionPlan")
			continue
		}
		ps.EnginesDeployed += 1
		ready := true
		for _, c := range item.Status.Conditions {
			if c.Status != "True" {
				ready = false
			}
		}
		if ready {
			planReachable[pid] += 1
		}
	}
	for planID, ps := range planStatuses {
		reachableEngines := planReachable[planID]
		ps.EnginesReachable = reachableEngines == ps.Engines
		// we only check if the plan is in progress if the engines are reachable
		if ps.EnginesReachable {
			rp, err := model.GetRunningPlan(collectionID, planID)
			if err == nil {
				ps.StartedTime = rp.StartedTime
				ps.InProgress = true
			}
		}
		cs.Plans = append(cs.Plans, ps)
	}
	return cs, nil
}

// This func is used by generateEngines as we need to fetch the engine urls per plan
func (cr *CloudRun) FetchEngineUrlsByPlan(collectionID, planID int64, opts *smodel.EngineOwnerRef) ([]string, error) {
	// need to make it get url by plan
	items, err := cr.getEnginesByCollectionPlan(collectionID, planID)
	if err != nil {
		return nil, err
	}
	m := []string{}
	for _, item := range items {
		m = append(m, item.Status.Url)
	}
	return m, nil
}

func (cr *CloudRun) GetDeployedCollections() (map[int64]time.Time, error) {
	deployCollections := make(map[int64]time.Time)
	resp, err := cr.rs.Namespaces.Services.List(cr.nsProjectID).Do()
	if err != nil {
		return deployCollections, err
	}
	for _, pod := range resp.Items {
		collectionID, err := strconv.ParseInt(pod.Metadata.Labels["collection"], 10, 64)
		if err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, pod.Metadata.CreationTimestamp)
		if err != nil {
			log.Printf("Error parsing creation timestamp '%s': %v", pod.Metadata.CreationTimestamp, err)
			t = time.Now() // fallback to current time
		}
		deployCollections[collectionID] = t
	}
	return deployCollections, nil
}

func (cr *CloudRun) GetPodsMetrics(collectionID, planID int64) (map[string]apiv1.ResourceList, error) {
	// For cloud run, pod metrics is not supported
	return nil, ErrFeatureUnavailable
}

// TODO: what we need is actually get the deployed engines account, not only ready ones.
// We also need to change this in k8s.go
func (cr *CloudRun) PodReadyCount(collectionID int64) int {
	items, err := cr.getEnginesByCollection(collectionID)
	if err != nil {
		return 0
	}
	return len(items)
}

func (cr *CloudRun) GetCollectionEnginesDetail(projectID, collectionID int64) (*smodel.CollectionDetails, error) {
	return nil, nil
}

func (cr *CloudRun) ExposeProject(projectID int64) error {
	return nil
}

func (cr *CloudRun) PurgeProjectIngress(projectID int64) error {
	return nil
}

func (cr *CloudRun) GetDeployedServices() (map[int64]time.Time, error) {
	return nil, nil
}

func (cr *CloudRun) GetEnginesByProject(projectID int64) ([]apiv1.Pod, error) {
	return nil, nil
}

func (cr *CloudRun) DownloadPodLog(collectionID, planID int64) (string, error) {
	// Cloud run API does not support fetching the logs now.
	engines, err := cr.getEnginesByCollectionPlan(collectionID, planID)
	if err != nil {
		return "", err
	}
	e := engines[0]
	engineUrl := e.Status.Url
	logUrl := fmt.Sprintf("%s/output", engineUrl)
	resp, err := cr.httpClient.Get(logUrl)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close response body")
		}
	}()
	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(r), nil
}
