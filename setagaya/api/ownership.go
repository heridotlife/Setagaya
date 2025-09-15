package api

import (
	"net/http"

	"github.com/julienschmidt/httprouter"

	"github.com/hveda/Setagaya/setagaya/model"
)

func (s *SetagayaAPI) hasProjectOwnership(project *model.Project, account *model.Account) bool {
	if s.enableRBAC && s.rbacIntegration != nil {
		return s.rbacIntegration.HasProjectOwnership(project, account)
	}

	// Fallback to legacy ownership check
	if _, ok := account.MLMap[project.Owner]; !ok {
		if !account.IsAdmin() {
			return false
		}
	}
	return true
}

func (s *SetagayaAPI) hasCollectionOwnership(r *http.Request, params httprouter.Params) (*model.Collection, error) {
	collection, err := getCollection(params.ByName("collection_id"))
	if err != nil {
		return nil, err
	}
	account, ok := r.Context().Value(accountKey).(*model.Account)
	if !ok {
		return nil, makeInvalidRequestError("account")
	}

	if s.enableRBAC && s.rbacIntegration != nil {
		if !s.rbacIntegration.HasCollectionOwnership(collection, account) {
			return nil, makeCollectionOwnershipError()
		}
	} else {
		// Fallback to legacy ownership check
		project, err := model.GetProject(collection.ProjectID)
		if err != nil {
			return nil, err
		}
		if r := s.hasProjectOwnership(project, account); !r {
			return nil, makeCollectionOwnershipError()
		}
	}

	return collection, nil
}
