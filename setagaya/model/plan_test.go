package model

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/hveda/Setagaya/setagaya/config"
)

func TestCreateAndGetPlan(t *testing.T) {
	// Skip database tests in test mode (when no real DB connection available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" || config.SC.DBC == nil {
		t.Skip("Skipping database test in test mode")
		return
	}

	name := "testplan"
	projectID := int64(1)
	planID, err := CreatePlan(name, projectID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := GetPlan(planID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, name, p.Name)
	assert.Equal(t, projectID, p.ProjectID)

	if err := p.Delete(); err != nil {
		t.Logf("Failed to delete plan: %v", err)
	}
	p, err = GetPlan(planID)
	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestGetRunningPlans(t *testing.T) {
	// Skip database tests in test mode (when no real DB connection available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" || config.SC.DBC == nil {
		t.Skip("Skipping database test in test mode")
		return
	}

	collectionID := int64(1)
	planID := int64(1)
	if err := AddRunningPlan(collectionID, planID); err != nil {
		t.Fatal(err)
	}
	rp, err := GetRunningPlan(collectionID, planID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, rp.PlanID, planID)
	assert.Equal(t, rp.CollectionID, collectionID)
	assert.NotNil(t, rp.StartedTime)
	rps, err := GetRunningPlans()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(rps))
	rp = rps[0]
	assert.Equal(t, rp.CollectionID, collectionID)
	assert.Equal(t, rp.PlanID, planID)

	if err := DeleteRunningPlan(collectionID, planID); err != nil {
		t.Logf("Failed to delete running plan: %v", err)
	}
	rps, err = GetRunningPlans()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 0, len(rps))

	// delete should be idempotent
	err = DeleteRunningPlan(collectionID, planID)
	assert.Equal(t, nil, err)
}

func TestMain(m *testing.M) {
	if err := setupAndTeardown(); err != nil {
		log.Fatal(err)
	}
	r := m.Run()
	if err := setupAndTeardown(); err != nil {
		log.Errorf("Failed to teardown: %v", err)
	}
	os.Exit(r)
}
