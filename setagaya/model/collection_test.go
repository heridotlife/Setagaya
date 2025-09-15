package model

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hveda/Setagaya/setagaya/config"
)

func TestCreateAndGetCollection(t *testing.T) {
	cleanup := SetupTestEnvironment(t)
	defer cleanup()

	// Skip database operations in test mode when using mock database
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" {
		t.Skip("Skipping database test in test mode")
	}

	name := "testcollection"
	projectID := int64(1)
	collectionID, err := CreateCollection(name, projectID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := GetCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, name, c.Name)
	assert.Equal(t, projectID, c.ProjectID)

	if err := c.Delete(); err != nil {
		t.Logf("Error deleting collection: %v", err)
	}
	c, err = GetCollection(collectionID)
	assert.NotNil(t, err)
	assert.Nil(t, c)
}
func TestAddPlanAndGet(t *testing.T) {
	// Skip database tests in test mode (when no real DB connection available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" || config.SC.DBC == nil {
		t.Skip("Skipping database test in test mode")
		return
	}

	projectID := int64(1)
	planName := "test"
	planID, err := CreatePlan(planName, projectID)
	if err != nil {
		t.Fatal(err)
	}
	collectionName := "collection"
	collectionID, err := CreateCollection(collectionName, projectID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := GetCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	ep := &ExecutionPlan{
		PlanID:      planID,
		Rampup:      1,
		Concurrency: 1,
		Duration:    1,
	}
	err = c.AddExecutionPlan(ep)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := GetPlan(ep.PlanID)
	using, _ := plan.IsBeingUsed()
	assert.Equal(t, using, true)
	eps, err := c.GetExecutionPlans()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(eps), 1)
	for _, ep := range eps {
		assert.Equal(t, planID, ep.PlanID)
	}

	ep.Duration = 2
	if err := c.AddExecutionPlan(ep); err != nil {
		t.Logf("Error adding execution plan: %v", err)
	}
	eps, err = c.GetExecutionPlans()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, eps[0].Duration, 2)

	if err := c.DeleteExecutionPlan(c.ID, planID); err != nil {
		t.Logf("Error deleting execution plan: %v", err)
	}
	using, _ = plan.IsBeingUsed()
	assert.Equal(t, using, false)
	eps, _ = c.GetExecutionPlans()
	assert.Equal(t, len(eps), 0)
}
func TestStorePlans(t *testing.T) {
	// Skip database tests in test mode (when no real DB connection available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" || config.SC.DBC == nil {
		t.Skip("Skipping database test in test mode")
		return
	}

	projectID := int64(1)
	planID1, err := CreatePlan("test1", projectID)
	if err != nil {
		t.Fatal(err)
	}
	planID2, err := CreatePlan("test2", projectID)
	if err != nil {
		t.Fatal(err)
	}
	collectionName := "collection"
	collectionID, err := CreateCollection(collectionName, projectID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := GetCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	ep1 := &ExecutionPlan{
		PlanID:      planID1,
		Rampup:      1,
		Concurrency: 1,
		Duration:    1,
	}
	ep2 := &ExecutionPlan{
		PlanID:      planID2,
		Rampup:      1,
		Concurrency: 1,
		Duration:    2,
	}
	ec := &ExecutionCollection{}
	ec.Tests = []*ExecutionPlan{ep1, ep2}
	err = c.Store(ec)
	if err != nil {
		t.Fatal(err)
	}
	eps, err := c.GetExecutionPlans()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, len(eps))

	ep1.Duration = 2
	ec = &ExecutionCollection{}
	ec.Tests = []*ExecutionPlan{ep1, ep2}
	err = c.Store(ec)
	assert.NoError(t, err)
	eps, _ = c.GetExecutionPlans()
	assert.Equal(t, 2, eps[0].Duration)

	ec = &ExecutionCollection{}
	ec.Tests = []*ExecutionPlan{ep1}
	err = c.Store(ec)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(eps))
}

func TestCollectionRuns(t *testing.T) {
	// Skip database tests in test mode (when no real DB connection available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" || config.SC.DBC == nil {
		t.Skip("Skipping database test in test mode")
		return
	}

	collectionName := "collection"
	collectionID, err := CreateCollection(collectionName, 1)
	if err != nil {
		t.Fatal(err)
	}
	c, err := GetCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	runID := int64(1)
	err = c.NewRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if finishErr := c.RunFinish(runID); finishErr != nil {
		t.Fatal(finishErr)
	}
	runs, err := c.GetRuns()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(runs))
	for _, r := range runs {
		assert.Equal(t, collectionID, r.CollectionID)
		assert.NotNil(t, r.StartedTime)
	}

}

func TestCollectionRun(t *testing.T) {
	// Skip database tests in test mode (when no real DB connection available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" || config.SC.DBC == nil {
		t.Skip("Skipping database test in test mode")
		return
	}

	collectionName := "collection"
	collectionID, err := CreateCollection(collectionName, 1)
	if err != nil {
		t.Fatal(err)
	}
	c, err := GetCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := c.GetCurrentRun()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, int64(0), runID)
	runIDExpected, err := c.StartRun()
	if err != nil {
		t.Fatal(err)
	}
	runID, err = c.GetCurrentRun()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, runIDExpected, runID)
	_, err = c.StartRun()
	assert.NotNil(t, err)

	if stopErr := c.StopRun(); stopErr != nil {
		t.Fatal(stopErr)
	}
	runID, err = c.GetCurrentRun()
	assert.NoError(t, err)
	assert.Equal(t, int64(0), runID)
}
