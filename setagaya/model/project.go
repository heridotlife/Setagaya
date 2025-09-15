package model

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/guregu/null"
	log "github.com/sirupsen/logrus"

	"github.com/hveda/Setagaya/setagaya/config"
)

type Project struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	ssID        null.String
	SID         string        `json:"sid"`
	TenantID    *int64        `json:"tenant_id,omitempty"`  // Added for multi-tenancy
	CreatedBy   string        `json:"created_by,omitempty"` // Okta User ID who created
	UpdatedBy   string        `json:"updated_by,omitempty"` // Okta User ID who last updated
	CreatedTime time.Time     `json:"created_time"`
	Collections []*Collection `json:"collections"`
	Plans       []*Plan       `json:"plans"`
}

func CreateProject(name, owner, sid string) (int64, error) {
	db := config.SC.DBC
	q, err := db.Prepare("insert project set name=?,owner=?,sid=?")
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()

	_sid := sql.NullString{
		String: sid,
		Valid:  true,
	}
	if sid == "" {
		_sid.Valid = false
	}

	r, err := q.Exec(name, owner, _sid)

	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}
	return id, nil
}

func GetProjectsByOwners(owners []string) ([]*Project, error) {
	db := config.SC.DBC
	r := []*Project{}

	if len(owners) == 0 {
		return r, nil
	}

	// Create placeholders for parameterized query
	placeholders := make([]string, len(owners))
	args := make([]interface{}, len(owners))
	for i, owner := range owners {
		placeholders[i] = "?"
		args[i] = owner
	}

	// #nosec G201 -- Using parameterized placeholders, not direct user input in SQL
	query := fmt.Sprintf("select id, name, owner, sid, created_time from project where owner in (%s)",
		strings.Join(placeholders, ","))
	q, err := db.Prepare(query)
	if err != nil {
		return r, err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()
	rows, err := q.Query(args...)
	if err != nil {
		return r, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close rows")
		}
	}()
	for rows.Next() {
		p := new(Project)
		if err := rows.Scan(&p.ID, &p.Name, &p.Owner, &p.ssID, &p.CreatedTime); err != nil {
			log.WithError(err).Error("Failed to scan project")
			continue
		}
		p.SID = p.ssID.String
		r = append(r, p)
	}
	err = rows.Err()
	if err != nil {
		return r, err
	}
	return r, nil
}

func GetProject(id int64) (*Project, error) {
	db := config.SC.DBC
	q, err := db.Prepare("select id, name, owner, sid, created_time from project where id=?")
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()

	project := new(Project)
	err = q.QueryRow(id).Scan(&project.ID, &project.Name, &project.Owner, &project.ssID, &project.CreatedTime)
	if err != nil {
		return nil, &DBError{Err: err, Message: "project not found"}
	}
	// TODO remove SSID as it's only supposed to be a temp solution
	project.SID = project.ssID.String
	return project, nil
}

func (p *Project) Delete() error {
	db := config.SC.DBC
	q, err := db.Prepare("delete from project where id=?")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()
	rs, err := q.Query(p.ID)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := rs.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close rows")
		}
	}()
	return nil
}

func (p *Project) GetCollections() ([]*Collection, error) {
	db := config.SC.DBC
	r := []*Collection{}
	q, err := db.Prepare("select id, name from collection where project_id=?")
	if err != nil {
		return r, err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()
	rows, err := q.Query(p.ID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close rows")
		}
	}()
	for rows.Next() {
		collection := new(Collection)
		if err := rows.Scan(&collection.ID, &collection.Name); err != nil {
			log.WithError(err).Error("Failed to scan collection")
			continue
		}
		r = append(r, collection)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (p *Project) GetPlans() ([]*Plan, error) {
	db := config.SC.DBC
	r := []*Plan{}
	q, err := db.Prepare("select id, name, project_id, created_time from plan where project_id=?")
	if err != nil {
		return r, err
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close prepared statement")
		}
	}()
	rows, err := q.Query(p.ID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.WithError(closeErr).Error("Failed to close rows")
		}
	}()
	for rows.Next() {
		plan := new(Plan)
		if err := rows.Scan(&plan.ID, &plan.Name, &plan.ProjectID, &plan.CreatedTime); err != nil {
			log.WithError(err).Error("Failed to scan plan")
			continue
		}
		r = append(r, plan)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return r, nil
}
