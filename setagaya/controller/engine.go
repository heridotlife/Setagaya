package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hveda/Setagaya/setagaya/config"
	enginesModel "github.com/hveda/Setagaya/setagaya/engines/model"
	"github.com/hveda/Setagaya/setagaya/model"
	sos "github.com/hveda/Setagaya/setagaya/object_storage"
	"github.com/hveda/Setagaya/setagaya/scheduler"
	smodel "github.com/hveda/Setagaya/setagaya/scheduler/model"
	"github.com/hveda/Setagaya/setagaya/utils"

	es "github.com/iandyh/eventsource"
	log "github.com/sirupsen/logrus"
)

type setagayaEngine interface {
	trigger(edc *enginesModel.EngineDataConfig) error
	deploy(scheduler.EngineScheduler) error
	subscribe(runID int64) error
	progress() bool
	readMetrics() chan *setagayaMetric
	reachable(*scheduler.K8sClientManager) bool
	closeStream()
	terminate(force bool) error
	EngineID() int
	updateEngineUrl(url string)
}

type engineType struct{}

var JmeterEngineType engineType

// HttPClient shared by the engines to contact with the container
// deployed in the k8s cluster
var engineHttpClient = &http.Client{
	Timeout: 30 * time.Second,
}

type setagayaMetric struct {
	threads      float64
	latency      float64
	label        string
	status       string
	raw          string
	collectionID string
	planID       string
	engineID     string
	runID        string
}

type baseEngine struct {
	engineUrl    string
	collectionID int64
	planID       int64
	projectID    int64
	ID           int
	stream       *es.Stream
	cancel       context.CancelFunc
	runID        int64
	*config.ExecutorContainer
}

func sendTriggerRequest(url string, edc *enginesModel.EngineDataConfig) (*http.Response, error) {
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(&edc); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return engineHttpClient.Do(req)
}

func (be *baseEngine) EngineID() int {
	return be.ID
}

func (be *baseEngine) makeBaseUrl() string {
	base := "%s/%s"
	if strings.Contains(be.engineUrl, "http") {
		return base
	}
	return "http://" + base
}

func (be *baseEngine) subscribe(runID int64) error {
	base := be.makeBaseUrl()
	streamUrl := fmt.Sprintf(base, be.engineUrl, "stream")
	req, err := http.NewRequest("GET", streamUrl, nil)
	if err != nil {
		return err
	}
	log.Printf("Subscribing to engine url %s", streamUrl)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	stream, err := es.SubscribeWith("", httpClient, req)
	if err != nil {
		cancel()
		return err
	}
	be.stream = stream
	be.cancel = cancel
	be.runID = runID
	return nil
}

func (be *baseEngine) progress() bool {
	base := be.makeBaseUrl()
	progressEndpoint := fmt.Sprintf(base, be.engineUrl, "progress")
	var resp *http.Response
	var httpError error
	err := utils.Retry(func() error {
		resp, httpError = engineHttpClient.Get(progressEndpoint)
		return httpError
	}, nil)
	if err != nil {
		return false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()
	return resp.StatusCode == http.StatusOK
}

func (be *baseEngine) reachable(manager *scheduler.K8sClientManager) bool {
	return manager.ServiceReachable(be.engineUrl)
}

func (be *baseEngine) closeStream() {
	be.cancel()
	be.stream.Close()
}

func (be *baseEngine) terminate(force bool) error {
	// If it's force, it means we are purging the collection
	// In this case, we don't send the stop request to test containers
	if force {
		return nil
	}
	base := be.makeBaseUrl()
	stopUrl := fmt.Sprintf(base, be.engineUrl, "stop")
	resp, err := engineHttpClient.Post(stopUrl, "application/x-www-form-urlencoded", nil)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()
	be.closeStream()
	return nil
}

func (be *baseEngine) deploy(manager scheduler.EngineScheduler) error {
	return manager.DeployEngine(be.projectID, be.collectionID, be.planID, be.ID, be.ExecutorContainer)
}

func (be *baseEngine) trigger(edc *enginesModel.EngineDataConfig) error {
	engineUrl := be.engineUrl
	base := be.makeBaseUrl()
	url := fmt.Sprintf(base, engineUrl, "start")
	return utils.Retry(func() error {
		resp, err := sendTriggerRequest(url, edc)
		if err != nil {
			return err
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Error closing response body: %v", err)
			}
		}()
		if resp.StatusCode == http.StatusConflict {
			log.Printf("%s is already triggered", engineUrl)
			return nil
		}
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: Some test files are missing. Please stop collection re-upload them", sos.FileNotFoundError())
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("engine failed to trigger: %d %s", resp.StatusCode, resp.Status)
		}
		log.Printf("%s is triggered", engineUrl)
		return nil
	}, sos.FileNotFoundError())
}

func (be *baseEngine) readMetrics() chan *setagayaMetric {
	log.Println("BaseEngine does not readMetrics(). Use an engine type.")
	return nil
}

func (be *baseEngine) updateEngineUrl(url string) {
	be.engineUrl = url
}

func findEngineConfig(et engineType) *config.ExecutorContainer {
	switch et {
	case JmeterEngineType:
		return config.SC.ExecutorConfig.JmeterContainer.ExecutorContainer
	}
	return nil
}

func generateEngines(enginesRequired int, planID, collectionID, projectID int64, et engineType) (engines []setagayaEngine, err error) {
	for i := 0; i < enginesRequired; i++ {
		engineC := &baseEngine{
			ID:           i,
			projectID:    projectID,
			collectionID: collectionID,
			planID:       planID,
		}
		var e setagayaEngine
		switch et {
		case JmeterEngineType:
			e = NewJmeterEngine(engineC)
		default:
			return nil, makeWrongEngineTypeError()
		}
		engines = append(engines, e)
	}
	return engines, nil
}

func generateEnginesWithUrl(enginesRequired int, planID, collectionID, projectID int64, et engineType, scheduler scheduler.EngineScheduler) (engines []setagayaEngine, err error) {
	engines, err = generateEngines(enginesRequired, planID, collectionID, projectID, et)
	if err != nil {
		return nil, err
	}
	engineUrls, err := scheduler.FetchEngineUrlsByPlan(collectionID, planID, &smodel.EngineOwnerRef{
		ProjectID:    projectID,
		EnginesCount: len(engines),
	})
	if err != nil {
		return nil, err
	}
	// This could happen during purging as there are still some engines lingering in the scheduler
	if len(engineUrls) != len(engines) {
		return nil, errors.New("engines in scheduler does not match")
	}
	for i, e := range engines {
		url := engineUrls[i]
		e.updateEngineUrl(url)
	}
	return engines, nil
}

func (ctr *Controller) fetchEngineMetrics() {
	for {
		time.Sleep(5 * time.Second)
		// compared to previous approach(getting the deploy collection from the target k8s cluster), this one can
		// reduce the engine metrics when there are multiple controller pointing to the same cluster
		deployedCollections, err := model.GetLaunchingCollectionByContext(config.SC.Context)
		if err != nil {
			continue
		}
		for _, collectionID := range deployedCollections {
			c, err := model.GetCollection(collectionID)
			if err != nil {
				continue
			}
			eps, err := c.GetExecutionPlans()
			if err != nil {
				continue
			}
			collectionID_str := strconv.FormatInt(collectionID, 10)
			for _, ep := range eps {
				podsMetrics, err := ctr.Scheduler.GetPodsMetrics(collectionID, ep.PlanID)
				if err != nil {
					// Some schedulers might not have the feature to expose the metrics
					// We will return directly
					log.Warn(err)
					if errors.Is(err, scheduler.ErrFeatureUnavailable) {
						return
					}
					continue
				}
				planID_str := strconv.FormatInt(ep.PlanID, 10)
				for engineNumber, metrics := range podsMetrics {
					for resourceName, m := range metrics {
						if resourceName == "cpu" {
							config.CpuGauge.WithLabelValues(collectionID_str, planID_str, engineNumber).Set(float64(m.MilliValue()))
						} else {
							config.MemGauge.WithLabelValues(collectionID_str, planID_str, engineNumber).Set(float64(m.Value()))
						}
					}
				}
			}
		}
	}
}
