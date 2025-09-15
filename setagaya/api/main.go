package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/hveda/Setagaya/setagaya/config"
	"github.com/hveda/Setagaya/setagaya/controller"
	"github.com/hveda/Setagaya/setagaya/model"
	"github.com/hveda/Setagaya/setagaya/object_storage"
	"github.com/hveda/Setagaya/setagaya/rbac"
	"github.com/hveda/Setagaya/setagaya/scheduler"
	smodel "github.com/hveda/Setagaya/setagaya/scheduler/model"
	utils "github.com/hveda/Setagaya/setagaya/utils"
)

type SetagayaAPI struct {
	ctr             *controller.Controller
	rbacIntegration *rbac.Integration
	enableRBAC      bool
}

func NewAPIServer() *SetagayaAPI {
	c := &SetagayaAPI{
		ctr:        controller.NewController(),
		enableRBAC: true, // TODO: Read from config
	}
	c.ctr.StartRunning()

	// Initialize RBAC integration
	if c.enableRBAC {
		integration, err := rbac.NewIntegration()
		if err != nil {
			log.WithError(err).Error("Failed to initialize RBAC integration")
			c.enableRBAC = false
		} else {
			c.rbacIntegration = integration
			log.Info("RBAC integration enabled for API server")
		}
	}

	return c
}

type JSONMessage struct {
	Message string `json:"message"`
}

func (s *SetagayaAPI) jsonise(w http.ResponseWriter, status int, content interface{}) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(content); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
}

func (s *SetagayaAPI) makeRespMessage(message string) *JSONMessage {
	return &JSONMessage{
		Message: message,
	}
}

func (s *SetagayaAPI) makeFailMessage(w http.ResponseWriter, message string, statusCode int) {
	messageObj := s.makeRespMessage(message)
	s.jsonise(w, statusCode, messageObj)
}

// handles errors from other packages, like model, scheduler, etc.
// unhandle errors will be returned
func (s *SetagayaAPI) handleErrorsFromExt(w http.ResponseWriter, err error) error {
	var (
		dbe                   *model.DBError
		noResourcesFoundError *scheduler.NoResourcesFoundErr
	)
	switch {
	case errors.As(err, &dbe):
		s.makeFailMessage(w, dbe.Error(), http.StatusNotFound)
		return nil
	case errors.As(err, &noResourcesFoundError):
		s.makeFailMessage(w, noResourcesFoundError.Message, http.StatusNotFound)
		return nil
	}
	return err
}

func (s *SetagayaAPI) handleErrors(w http.ResponseWriter, err error) {
	unhandledError := s.handleErrorsFromExt(w, err)
	if unhandledError != nil { // if unhandleError is not nil, it's the same as original error
		switch {
		case errors.Is(err, errNoPermission):
			s.makeFailMessage(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, errInvalidRequest):
			s.makeFailMessage(w, err.Error(), http.StatusBadRequest)
		default:
			log.Printf("api error: %v", err)
			s.makeFailMessage(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (s *SetagayaAPI) projectsGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}

	// Parse query parameters for optional includes
	includeOptions := s.parseProjectIncludes(r.URL.Query())

	// Get projects with RBAC-aware filtering
	projects, err := s.getProjectsWithRBACFilter(account)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	// Return simple projects if no includes requested
	if !includeOptions.includeCollections && !includeOptions.includePlans {
		s.jsonise(w, http.StatusOK, projects)
		return
	}

	// Enhance projects with requested includes
	s.enhanceProjectsWithIncludes(projects, includeOptions)
	s.jsonise(w, http.StatusOK, projects)
}

// projectIncludeOptions defines what to include in project response
type projectIncludeOptions struct {
	includeCollections bool
	includePlans       bool
}

// parseProjectIncludes parses query parameters for project includes
func (s *SetagayaAPI) parseProjectIncludes(qs url.Values) projectIncludeOptions {
	options := projectIncludeOptions{}

	includeCollectionsList := qs["include_collections"]
	includePlansList := qs["include_plans"]

	if len(includeCollectionsList) > 0 {
		if includeCollections, err := strconv.ParseBool(includeCollectionsList[0]); err == nil {
			options.includeCollections = includeCollections
		}
	}

	if len(includePlansList) > 0 {
		if includePlans, err := strconv.ParseBool(includePlansList[0]); err == nil {
			options.includePlans = includePlans
		}
	}

	return options
}

// getProjectsWithRBACFilter gets projects with RBAC-aware filtering when enabled
func (s *SetagayaAPI) getProjectsWithRBACFilter(account *model.Account) ([]*model.Project, error) {
	if s.enableRBAC && s.rbacIntegration != nil {
		return s.getProjectsViaRBAC(account)
	}

	// Fallback to legacy method
	return model.GetProjectsByOwners(account.ML)
}

// getProjectsViaRBAC attempts to get projects via RBAC with fallback
func (s *SetagayaAPI) getProjectsViaRBAC(account *model.Account) ([]*model.Project, error) {
	// Use RBAC-aware project filtering
	result, rbacErr := s.rbacIntegration.GetProjectsByOwnersWithTenantFilter(account.ML, account)
	if rbacErr != nil || result == nil {
		// Fall back to legacy method if RBAC filtering fails
		return model.GetProjectsByOwners(account.ML)
	}

	// Type assert the result
	if projectList, ok := result.([]*model.Project); ok {
		return projectList, nil
	}

	// Fallback if type assertion fails
	return model.GetProjectsByOwners(account.ML)
}

// enhanceProjectsWithIncludes adds collections and/or plans to projects as requested
func (s *SetagayaAPI) enhanceProjectsWithIncludes(projects []*model.Project, options projectIncludeOptions) {
	for _, p := range projects {
		if options.includeCollections {
			if collections, err := p.GetCollections(); err == nil {
				p.Collections = collections
			}
		}
		if options.includePlans {
			if plans, err := p.GetPlans(); err == nil {
				p.Plans = plans
			}
		}
	}
}

func (s *SetagayaAPI) projectGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	project, err := getProject(params.ByName("project_id"))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	s.jsonise(w, http.StatusOK, project)
}

func (s *SetagayaAPI) projectUpdateHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

func (s *SetagayaAPI) projectCreateHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.handleErrors(w, makeInvalidRequestError("failed to parse form"))
		return
	}
	name := r.Form.Get("name")
	if name == "" {
		s.handleErrors(w, makeInvalidRequestError("Project name cannot be empty"))
		return
	}
	owner := r.Form.Get("owner")
	if owner == "" {
		s.handleErrors(w, makeInvalidRequestError("Owner name cannot be empty"))
		return
	}
	if _, ok := account.MLMap[owner]; !ok {
		s.handleErrors(w, makeNoPermissionErr(fmt.Sprintf("You are not part of %s", owner)))
		return
	}
	var sid string
	if config.SC.EnableSid {
		sid = r.Form.Get("sid")
		if sid == "" {
			s.handleErrors(w, makeInvalidRequestError("SID cannot be empty"))
			return
		}
		if _, err := strconv.Atoi(sid); err != nil {
			s.handleErrors(w, makeInvalidRequestError("SID is invalid"))
			return
		}
	}
	projectID, err := model.CreateProject(name, owner, sid)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	project, err := model.GetProject(projectID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	s.jsonise(w, http.StatusOK, project)
}

func (s *SetagayaAPI) projectDeleteHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}
	project, err := getProject(params.ByName("project_id"))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if r := s.hasProjectOwnership(project, account); !r {
		s.handleErrors(w, makeProjectOwnershipError())
		return
	}
	collectionIDs, err := project.GetCollections()
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if len(collectionIDs) > 0 {
		s.handleErrors(w, makeInvalidRequestError("You cannot delete a project that has collections"))
		return
	}
	planIDs, err := project.GetPlans()
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if len(planIDs) > 0 {
		s.handleErrors(w, makeInvalidRequestError("You cannot delete a project that has plans"))
		return
	}
	if err := project.Delete(); err != nil {
		s.handleErrors(w, err)
		return
	}
	s.jsonise(w, http.StatusOK, s.makeRespMessage("Project deleted successfully"))
}

func (s *SetagayaAPI) planGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	plan, err := getPlan(params.ByName("plan_id"))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	s.jsonise(w, http.StatusOK, plan)
}

func (s *SetagayaAPI) planUpdateHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

type AdminCollectionResponse struct {
	RunningCollections []*model.RunningPlan `json:"running_collections"`
	NodePools          smodel.AllNodesInfo  `json:"node_pools"`
}

func (s *SetagayaAPI) collectionAdminGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collections, err := model.GetRunningCollections()
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	acr := new(AdminCollectionResponse)
	acr.RunningCollections = collections
	s.jsonise(w, http.StatusOK, acr)
}

// RBAC Tenant Management Handlers

func (s *SetagayaAPI) tenantCreateHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	if !s.enableRBAC {
		s.handleErrors(w, makeAPIDisabledError("RBAC not enabled"))
		return
	}

	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}

	// Only service providers can create tenants
	userContext, err := s.rbacIntegration.GetUserContext(r.Context(), account.Name)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	if !userContext.IsServiceProvider {
		s.handleErrors(w, makeNoPermissionErr("Only service providers can create tenants"))
		return
	}

	var tenant rbac.Tenant
	if decodeErr := json.NewDecoder(r.Body).Decode(&tenant); decodeErr != nil {
		s.handleErrors(w, makeInvalidRequestError("Invalid JSON payload"))
		return
	}

	// Validate required fields
	if tenant.Name == "" {
		s.handleErrors(w, makeInvalidRequestError("Tenant name cannot be empty"))
		return
	}

	if tenant.DisplayName == "" {
		s.handleErrors(w, makeInvalidRequestError("Tenant display name cannot be empty"))
		return
	}

	// Create tenant
	engine, err := s.rbacIntegration.GetRBACEngine()
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	createdTenant, err := engine.CreateTenant(r.Context(), &tenant)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	s.jsonise(w, http.StatusCreated, createdTenant)
}

func (s *SetagayaAPI) tenantsGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	if !s.enableRBAC {
		s.handleErrors(w, makeAPIDisabledError("RBAC not enabled"))
		return
	}

	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}

	userContext, err := s.rbacIntegration.GetUserContext(r.Context(), account.Name)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	engine, err := s.rbacIntegration.GetRBACEngine()
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	var tenants []*rbac.Tenant
	if userContext.IsServiceProvider {
		// Service providers can see all tenants
		allTenants, listErr := engine.ListTenants(r.Context(), "")
		if listErr != nil {
			s.handleErrors(w, listErr)
			return
		}
		for i := range allTenants {
			tenants = append(tenants, &allTenants[i])
		}
	} else {
		// Regular users can only see tenants they have access to
		tenants, err = engine.GetAccessibleTenants(r.Context(), userContext)
		if err != nil {
			s.handleErrors(w, err)
			return
		}
	}

	s.jsonise(w, http.StatusOK, tenants)
}

func (s *SetagayaAPI) tenantGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	if !s.enableRBAC {
		s.handleErrors(w, makeAPIDisabledError("RBAC not enabled"))
		return
	}

	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}

	tenantIDStr := params.ByName("tenant_id")
	tenantID, err := strconv.ParseInt(tenantIDStr, 10, 64)
	if err != nil {
		s.handleErrors(w, makeInvalidRequestError("Invalid tenant ID"))
		return
	}

	userContext, err := s.rbacIntegration.GetUserContext(r.Context(), account.Name)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	engine, err := s.rbacIntegration.GetRBACEngine()
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	// Check if user has access to this tenant
	if !userContext.IsServiceProvider && !userContext.HasTenantAccess(tenantID) {
		s.handleErrors(w, makeNoPermissionErr("Access denied to tenant"))
		return
	}

	tenant, err := engine.GetTenant(r.Context(), tenantID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	s.jsonise(w, http.StatusOK, tenant)
}

func (s *SetagayaAPI) tenantUpdateHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	if !s.enableRBAC {
		s.handleErrors(w, makeAPIDisabledError("RBAC not enabled"))
		return
	}

	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}

	tenantIDStr := params.ByName("tenant_id")
	tenantID, err := strconv.ParseInt(tenantIDStr, 10, 64)
	if err != nil {
		s.handleErrors(w, makeInvalidRequestError("Invalid tenant ID"))
		return
	}

	userContext, err := s.rbacIntegration.GetUserContext(r.Context(), account.Name)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	// Check if user can update this tenant (service provider or tenant admin)
	canUpdate := userContext.IsServiceProvider || userContext.HasTenantRole(tenantID, "tenant_admin")
	if !canUpdate {
		s.handleErrors(w, makeNoPermissionErr("Insufficient permissions to update tenant"))
		return
	}

	var updates rbac.Tenant
	if decodeErr := json.NewDecoder(r.Body).Decode(&updates); decodeErr != nil {
		s.handleErrors(w, makeInvalidRequestError("Invalid JSON payload"))
		return
	}

	// Set the tenant ID for the update
	updates.ID = tenantID

	engine, err := s.rbacIntegration.GetRBACEngine()
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	updatedTenant, err := engine.UpdateTenant(r.Context(), &updates)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	s.jsonise(w, http.StatusOK, updatedTenant)
}

func (s *SetagayaAPI) tenantDeleteHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	if !s.enableRBAC {
		s.handleErrors(w, makeAPIDisabledError("RBAC not enabled"))
		return
	}

	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}

	tenantIDStr := params.ByName("tenant_id")
	tenantID, err := strconv.ParseInt(tenantIDStr, 10, 64)
	if err != nil {
		s.handleErrors(w, makeInvalidRequestError("Invalid tenant ID"))
		return
	}

	userContext, err := s.rbacIntegration.GetUserContext(r.Context(), account.Name)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	// Only service providers can delete tenants
	if !userContext.IsServiceProvider {
		s.handleErrors(w, makeNoPermissionErr("Only service providers can delete tenants"))
		return
	}

	engine, err := s.rbacIntegration.GetRBACEngine()
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	err = engine.DeleteTenant(r.Context(), tenantID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *SetagayaAPI) planCreateHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.handleErrors(w, makeInvalidRequestError("failed to parse form"))
		return
	}
	projectID := r.Form.Get("project_id")
	project, err := getProject(projectID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if r := s.hasProjectOwnership(project, account); !r {
		s.handleErrors(w, makeProjectOwnershipError())
		return
	}
	name := r.Form.Get("name")
	if name == "" {
		s.handleErrors(w, makeInvalidRequestError("plan name cannot be empty"))
		return
	}
	planID, err := model.CreatePlan(name, project.ID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	plan, err := model.GetPlan(planID)
	if err != nil {
		s.handleErrors(w, err)
	}
	s.jsonise(w, http.StatusOK, plan)
}

func (s *SetagayaAPI) planDeleteHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}
	plan, err := getPlan(params.ByName("plan_id"))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	project, err := model.GetProject(plan.ProjectID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if r := s.hasProjectOwnership(project, account); !r {
		s.handleErrors(w, makeProjectOwnershipError())
		return
	}
	using, err := plan.IsBeingUsed()
	if err != nil {
		s.handleErrors(w, err)
		return

	}
	if using {
		s.handleErrors(w, makeInvalidRequestError("plan is being used"))
		return
	}
	if err := plan.Delete(); err != nil {
		s.handleErrors(w, err)
		return
	}
}

func (s *SetagayaAPI) planFilesUploadHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	plan, err := getPlan(params.ByName("plan_id"))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if parseErr := r.ParseMultipartForm(100 << 20); parseErr != nil { //parse 100 MB of data
		s.handleErrors(w, makeInvalidRequestError("failed to parse multipart form"))
		return
	}
	file, handler, err := r.FormFile("planFile")
	if err != nil {
		s.handleErrors(w, makeInvalidRequestError("Something wrong with file you uploaded"))
		return
	}
	err = plan.StoreFile(file, handler.Filename)
	if err != nil {
		// TODO need to handle the upload error here
		s.handleErrors(w, err)
		return
	}
	if _, err := w.Write([]byte("success")); err != nil {
		log.Printf("Error writing success response: %v", err)
	}
}

func (s *SetagayaAPI) planFilesGetHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

func (s *SetagayaAPI) collectionFilesGetHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

func (s *SetagayaAPI) collectionFilesUploadHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if parseErr := r.ParseMultipartForm(100 << 20); parseErr != nil { //parse 100 MB of data
		s.handleErrors(w, makeInvalidRequestError("failed to parse multipart form"))
		return
	}
	file, handler, err := r.FormFile("collectionFile")
	if err != nil {
		s.handleErrors(w, makeInvalidRequestError("Something wrong with file you uploaded"))
		return
	}
	err = collection.StoreFile(file, handler.Filename)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if _, err := w.Write([]byte("success")); err != nil {
		log.Printf("Error writing success response: %v", err)
	}
}

func (s *SetagayaAPI) collectionFilesDeleteHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if parseErr := r.ParseForm(); parseErr != nil {
		s.handleErrors(w, makeInvalidRequestError("failed to parse form"))
		return
	}
	filename := r.Form.Get("filename")
	if filename == "" {
		s.handleErrors(w, makeInvalidRequestError("Collection file name cannot be empty"))
		return
	}
	err = collection.DeleteFile(filename)
	if err != nil {
		s.handleErrors(w, makeInternalServerError("Deletion was unsuccessful"))
		return
	}
	if _, err := w.Write([]byte("Deleted successfully")); err != nil {
		log.Printf("Error writing deletion response: %v", err)
	}
}

func (s *SetagayaAPI) planFilesDeleteHandler(w http.ResponseWriter, r *http.Request, param httprouter.Params) {
	plan, err := getPlan(param.ByName("plan_id"))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if parseErr := r.ParseForm(); parseErr != nil {
		s.handleErrors(w, makeInvalidRequestError("failed to parse form"))
		return
	}
	filename := r.Form.Get("filename")
	if filename == "" {
		s.handleErrors(w, makeInvalidRequestError("plan file name cannot be empty"))
		return
	}
	err = plan.DeleteFile(filename)
	if err != nil {
		s.handleErrors(w, makeInternalServerError("Deletetion was unsuccessful"))
		return
	}
	if _, err := w.Write([]byte("Deleted successfully")); err != nil {
		log.Printf("Error writing deletion response: %v", err)
	}
}

func (s *SetagayaAPI) collectionCreateHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		s.handleErrors(w, makeInvalidRequestError("account"))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.handleErrors(w, makeInvalidRequestError("failed to parse form"))
		return
	}
	collectionName := r.Form.Get("name")
	if collectionName == "" {
		s.handleErrors(w, makeInvalidRequestError("collection name cannot be empty"))
		return
	}
	projectID := r.Form.Get("project_id")
	project, err := getProject(projectID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if r := s.hasProjectOwnership(project, account); !r {
		s.handleErrors(w, makeProjectOwnershipError())
		return
	}
	collectionID, err := model.CreateCollection(collectionName, project.ID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	collection, err := model.GetCollection(int64(collectionID))
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	s.jsonise(w, http.StatusOK, collection)
}

func (s *SetagayaAPI) collectionDeleteHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if s.ctr.Scheduler.PodReadyCount(collection.ID) > 0 {
		s.handleErrors(w, makeInvalidRequestError("You cannot launch engines when there are engines already deployed"))
		return
	}
	runningPlans, err := model.GetRunningPlansByCollection(collection.ID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if len(runningPlans) > 0 {
		s.handleErrors(w, makeInvalidRequestError("You cannot delete the collection during testing period"))
		return
	}
	if err := collection.Delete(); err != nil {
		s.handleErrors(w, err)
		return
	}
}

func (s *SetagayaAPI) collectionGetHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	// we ignore errors here as the front end will do the retry
	if executionPlans, err := collection.GetExecutionPlans(); err == nil {
		collection.ExecutionPlans = executionPlans
	}
	if runHistories, err := collection.GetRuns(); err == nil {
		collection.RunHistories = runHistories
	}
	s.jsonise(w, http.StatusOK, collection)
}

func hasInvalidDiff(curr, updated []*model.ExecutionPlan) (bool, string) {
	if len(updated) != len(curr) {
		return true, "You cannot add/remove plans while have engines deployed"
	}
	currCache := make(map[int64]*model.ExecutionPlan)
	for _, item := range curr {
		currCache[item.PlanID] = item
	}
	for _, item := range updated {
		currPlan, ok := currCache[item.PlanID]
		if !ok {
			return true, "You cannot add a new plan while having engines deployed"
		}
		if currPlan.Engines != item.Engines {
			return true, "You cannot change engine numbers while having engines deployed"
		}
		if currPlan.Concurrency != item.Concurrency {
			return true, "You cannot change concurrency while having engines deployed"
		}
	}
	return false, ""
}

func (s *SetagayaAPI) collectionUpdateHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

// parseCollectionUpload extracts and validates the uploaded YAML file
func (s *SetagayaAPI) parseCollectionUpload(r *http.Request) (*model.ExecutionWrapper, error) {
	if parseErr := r.ParseMultipartForm(1 << 20); parseErr != nil { //parse 1 MB of data
		return nil, makeInvalidRequestError("form")
	}

	file, _, err := r.FormFile("collectionYAML")
	if err != nil {
		return nil, makeInvalidResourceError("file")
	}

	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, makeInvalidRequestError("invalid file")
	}

	e := new(model.ExecutionWrapper)
	err = yaml.Unmarshal(raw, e)
	if err != nil {
		return nil, makeInvalidRequestError(err.Error())
	}

	return e, nil
}

// validateExecutionPlans validates that all plans belong to the same project and calculates total engines
func (s *SetagayaAPI) validateExecutionPlans(project *model.Project, tests []*model.ExecutionPlan) (int, error) {
	totalEnginesRequired := 0

	for _, ep := range tests {
		if ep.Engines <= 0 {
			return 0, makeInvalidRequestError("You cannot configure a plan with zero engine")
		}

		plan, planErr := model.GetPlan(ep.PlanID)
		if planErr != nil {
			return 0, planErr
		}

		planProject, projectErr := model.GetProject(plan.ProjectID)
		if projectErr != nil {
			return 0, projectErr
		}

		if project.ID != planProject.ID {
			return 0, makeInvalidRequestError("You can only add plan within the same project")
		}

		totalEnginesRequired += ep.Engines
	}

	return totalEnginesRequired, nil
}

// validateCollectionState checks if collection can be modified
func (s *SetagayaAPI) validateCollectionState(collection *model.Collection, newTests []*model.ExecutionPlan) error {
	runningPlans, err := model.GetRunningPlansByCollection(collection.ID)
	if err != nil {
		return err
	}

	if len(runningPlans) > 0 {
		return makeInvalidRequestError("You cannot change the collection during testing period")
	}

	if s.ctr.Scheduler.PodReadyCount(collection.ID) > 0 {
		currentPlans, plansErr := collection.GetExecutionPlans()
		if plansErr != nil {
			return plansErr
		}
		if ok, message := hasInvalidDiff(currentPlans, newTests); ok {
			return makeInvalidRequestError(message)
		}
	}

	return nil
}

func (s *SetagayaAPI) collectionUploadHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	e, err := s.parseCollectionUpload(r)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	if e.Content.CollectionID != collection.ID {
		s.handleErrors(w, makeInvalidRequestError("collection ID mismatch"))
		return
	}

	project, err := model.GetProject(collection.ProjectID)
	if err != nil {
		log.Error(err)
		s.handleErrors(w, err)
		return
	}

	totalEnginesRequired, err := s.validateExecutionPlans(project, e.Content.Tests)
	if err != nil {
		s.handleErrors(w, err)
		return
	}

	if totalEnginesRequired > config.SC.ExecutorConfig.MaxEnginesInCollection {
		errMsg := fmt.Sprintf("You are reaching the resource limit of the cluster. Requesting engines: %d, limit: %d.",
			totalEnginesRequired, config.SC.ExecutorConfig.MaxEnginesInCollection)
		s.handleErrors(w, makeInvalidRequestError(errMsg))
		return
	}

	if validateErr := s.validateCollectionState(collection, e.Content.Tests); validateErr != nil {
		s.handleErrors(w, validateErr)
		return
	}

	err = collection.Store(e.Content)
	if err != nil {
		s.handleErrors(w, err)
	}
}

func (s *SetagayaAPI) collectionEnginesDetailHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	collectionDetails, err := s.ctr.Scheduler.GetCollectionEnginesDetail(collection.ProjectID, collection.ID)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	s.jsonise(w, http.StatusOK, collectionDetails)
}

func (s *SetagayaAPI) collectionDeploymentHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if err := s.ctr.DeployCollection(collection); err != nil {
		var dbe *model.DBError
		if errors.As(err, &dbe) {
			s.handleErrors(w, makeInvalidRequestError(err.Error()))
			return
		}
		s.handleErrors(w, makeInternalServerError(err.Error()))
		return
	}
}

func (s *SetagayaAPI) collectionTriggerHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if err := s.ctr.TriggerCollection(collection); err != nil {
		s.handleErrors(w, err)
		return
	}
}

func (s *SetagayaAPI) collectionTermHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if err := s.ctr.TermCollection(collection, false); err != nil {
		s.handleErrors(w, makeInternalServerError(err.Error()))
		return
	}
}

func (s *SetagayaAPI) collectionStatusHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	collectionStatus, err := s.ctr.CollectionStatus(collection)
	if err != nil {
		s.handleErrors(w, err)
	}
	s.jsonise(w, http.StatusOK, collectionStatus)
}

func (s *SetagayaAPI) collectionPurgeHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	if err = s.ctr.TermAndPurgeCollection(collection); err != nil {
		s.handleErrors(w, err)
		return
	}
}

func (s *SetagayaAPI) planLogHandler(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collectionID, err := strconv.Atoi(params.ByName("collection_id"))
	if err != nil {
		s.handleErrors(w, makeInvalidResourceError("collection_id"))
		return
	}
	planID, err := strconv.Atoi(params.ByName("plan_id"))
	if err != nil {
		s.handleErrors(w, makeInvalidResourceError("plan_id"))
		return
	}
	content, err := s.ctr.Scheduler.DownloadPodLog(int64(collectionID), int64(planID))
	if err != nil {
		s.handleErrors(w, makeInvalidRequestError(err.Error()))
		return
	}
	m := make(map[string]string)
	m["c"] = content
	s.jsonise(w, http.StatusOK, m)
}

func (s *SetagayaAPI) streamCollectionMetrics(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	collection, err := s.hasCollectionOwnership(r, params)
	if err != nil {
		s.handleErrors(w, err)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientIP := retrieveClientIP(r)
	item := &controller.ApiMetricStream{
		StreamClient: make(chan *controller.ApiMetricStreamEvent),
		CollectionID: fmt.Sprintf("%d", collection.ID),
		ClientID:     fmt.Sprintf("%s-%s", clientIP, utils.RandStringRunes(6)),
	}
	s.ctr.ApiNewClients <- item

	// Use context for connection closure detection (safer than deprecated CloseNotifier)
	ctx := r.Context()
	go func() {
		<-ctx.Done()
		s.ctr.ApiClosingClients <- item
	}()
	for event := range item.StreamClient {
		if event == nil {
			continue
		}
		s, err := json.Marshal(event)
		if err != nil {
			if _, writeErr := fmt.Fprintf(w, "data:%v\n\n", err); writeErr != nil {
				log.Printf("Error writing to response: %v", writeErr)
			}
		} else {
			if _, writeErr := fmt.Fprintf(w, "data:%s\n\n", s); writeErr != nil {
				log.Printf("Error writing to response: %v", writeErr)
			}
		}
		flusher.Flush()
	}
}

func (s *SetagayaAPI) runGetHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

func (s *SetagayaAPI) runDeleteHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.jsonise(w, http.StatusNotImplemented, nil)
}

func (s *SetagayaAPI) fileDownloadHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	kind := params.ByName("kind")
	id := params.ByName("id")
	name := params.ByName("name")
	filename := fmt.Sprintf("%s/%s/%s", kind, id, name)

	data, err := object_storage.Client.Storage.Download(filename)
	if err != nil {
		s.jsonise(w, http.StatusNotFound, "not found")
		return
	}
	r := bytes.NewReader(data)
	w.Header().Add("Content-Disposition", "Attachment")
	http.ServeContent(w, req, filename, time.Now(), r)
}

type Route struct {
	Name        string
	Method      string
	Path        string
	HandlerFunc httprouter.Handle
}

type Routes []*Route

func (s *SetagayaAPI) InitRoutes() Routes {
	routes := Routes{
		&Route{"get_projects", "GET", "/api/projects", s.projectsGetHandler},
		&Route{"create_project", "POST", "/api/projects", s.projectCreateHandler},
		&Route{"delete_project", "DELETE", "/api/projects/:project_id", s.projectDeleteHandler},
		&Route{"get_project", "GET", "/api/projects/:project_id", s.projectGetHandler},
		&Route{"update_project", "PUT", "/api/projects/:project_id", s.projectUpdateHandler},

		&Route{"create_plan", "POST", "/api/plans", s.planCreateHandler},
		&Route{"get_plan", "GET", "/api/plans/:plan_id", s.planGetHandler},
		&Route{"update_plan", "PUT", "/api/plans/:plan_id", s.planUpdateHandler},
		&Route{"delete_plan", "DELETE", "/api/plans/:plan_id", s.planDeleteHandler},
		&Route{"get_plan_files", "GET", "/api/plans/:plan_id/files", s.planFilesGetHandler},
		&Route{"upload_plan_files", "PUT", "/api/plans/:plan_id/files", s.planFilesUploadHandler},
		&Route{"delete_plan_files", "DELETE", "/api/plans/:plan_id/files", s.planFilesDeleteHandler},

		&Route{"create_collection", "POST", "/api/collections", s.collectionCreateHandler},
		&Route{"delete_collection", "DELETE", "/api/collections/:collection_id", s.collectionDeleteHandler},
		&Route{"get_collection", "GET", "/api/collections/:collection_id", s.collectionGetHandler},
		&Route{"edit_collection", "PUT", "/api/collections/:collection_id", s.collectionUpdateHandler},
		&Route{"get_collection_files", "GET", "/api/collections/:collection_id/files", s.collectionFilesGetHandler},
		&Route{"upload_collection_files", "PUT", "/api/collections/:collection_id/files", s.collectionFilesUploadHandler},
		&Route{"delete_collection_files", "DELETE", "/api/collections/:collection_id/files", s.collectionFilesDeleteHandler},
		&Route{"get_collection_engines_detail", "GET", "/api/collections/:collection_id/engines_detail", s.collectionEnginesDetailHandler},
		&Route{"deploy", "POST", "/api/collections/:collection_id/deploy", s.collectionDeploymentHandler},
		&Route{"trigger", "POST", "/api/collections/:collection_id/trigger", s.collectionTriggerHandler},
		&Route{"stop", "POST", "/api/collections/:collection_id/stop", s.collectionTermHandler},
		&Route{"purge", "POST", "/api/collections/:collection_id/purge", s.collectionPurgeHandler},
		&Route{"get_runs", "GET", "/api/collections/:collection_id/runs", s.runGetHandler},
		&Route{"get_run", "GET", "/api/collections/:collection_id/runs/:run_id", s.runGetHandler},
		&Route{"delete_runs", "DELETE", "/api/collections/:collection_id/runs", s.runDeleteHandler},
		&Route{"delete_run", "DELETE", "/api/collections/:collection_id/runs/:run_id", s.runDeleteHandler},
		&Route{"status", "GET", "/api/collections/:collection_id/status", s.collectionStatusHandler},
		&Route{"stream", "GET", "/api/collections/:collection_id/stream", s.streamCollectionMetrics},
		&Route{"get_plan_log", "GET", "/api/collections/:collection_id/logs/:plan_id", s.planLogHandler},
		&Route{"upload_collection_config", "PUT", "/api/collections/:collection_id/config", s.collectionUploadHandler},
		&Route{"get_collection_config", "GET", "/api/collections/:collection_id/config", s.collectionConfigGetHandler},

		&Route{"files", "GET", "/api/files/:kind/:id/:name", s.fileDownloadHandler},

		&Route{"usage_summary", "GET", "/api/usage/summary", s.usageSummaryHandler},
		&Route{"usage_summary_by_sid", "GET", "/api/usage/summary_sid", s.usageSummaryHandlerBySid},

		&Route{"admin_collections", "GET", "/api/admin/collections", s.collectionAdminGetHandler},

		// RBAC Tenant Management endpoints
		&Route{"create_tenant", "POST", "/api/tenants", s.tenantCreateHandler},
		&Route{"get_tenants", "GET", "/api/tenants", s.tenantsGetHandler},
		&Route{"get_tenant", "GET", "/api/tenants/:tenant_id", s.tenantGetHandler},
		&Route{"update_tenant", "PUT", "/api/tenants/:tenant_id", s.tenantUpdateHandler},
		&Route{"delete_tenant", "DELETE", "/api/tenants/:tenant_id", s.tenantDeleteHandler},
	}
	for _, r := range routes {
		// TODO! We don't require auth for usage endpoint for now.
		if strings.Contains(r.Path, "usage") {
			continue
		}

		// Apply RBAC authorization if available, otherwise fallback to legacy auth
		if s.enableRBAC && s.rbacIntegration != nil {
			r.HandlerFunc = s.rbacIntegration.GetMiddleware().AuthorizeRequest(r.HandlerFunc)
		} else {
			r.HandlerFunc = s.authRequired(r.HandlerFunc)
		}
	}
	return routes
}
