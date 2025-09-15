package api

import (
	"errors"
	"fmt"
)

var (
	errNoPermission   = errors.New("403-")
	errInvalidRequest = errors.New("400-")
	ErrServer         = errors.New("500-")
)

func makeLoginError() error {
	return fmt.Errorf("%wyou need to login", errNoPermission)
}

func makeInvalidRequestError(message string) error {
	return fmt.Errorf("%w%s", errInvalidRequest, message)
}

func makeNoPermissionErr(message string) error {
	return fmt.Errorf("%w%s", errNoPermission, message)
}

func makeInternalServerError(message string) error {
	return fmt.Errorf("%w%s", ErrServer, message)
}

// you don't have permission error can be put into func
// invalid id can be put into func
func makeInvalidResourceError(resource string) error {
	return fmt.Errorf("%winvalid %s", errInvalidRequest, resource)
}

func makeProjectOwnershipError() error {
	return fmt.Errorf("%w%s", errNoPermission, "You don't own the project")
}

func makeCollectionOwnershipError() error {
	return fmt.Errorf("%w%s", errNoPermission, "You don't own the collection")
}

func makeAPIDisabledError(message string) error {
	return fmt.Errorf("%w%s", errInvalidRequest, message)
}
