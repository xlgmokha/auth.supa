package api

import (
	"errors"
	"net/http"

	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
)

func scimError(err error) error {
	switch {
	case models.IsNotFoundError(err):
		return errSCIMNotFound()
	case errors.Is(err, models.ErrSCIMStale):
		return errSCIMStale()
	case errors.Is(err, models.ErrSCIMGroupConflict):
		return scimerrors.ErrUniqueness(`"externalId" must be unique`)
	case errors.Is(err, models.ErrSCIMGroupMemberNotFound):
		return errSCIMMemberNotFound()
	case errors.Is(err, models.ErrSCIMGroupCycle):
		return scimerrors.ErrInvalidValue(`"members" must not create a group cycle`)
	case errors.Is(err, models.ErrSCIMUserConflict):
		return scimerrors.ErrUniqueness(`"userName" and "externalId" must be unique`)
	}
	return err
}

func errSCIMNotFound() error {
	return scimerrors.ErrNotFound("resource not found")
}

func errSCIMStale() error {
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func errSCIMMemberNotFound() error {
	return scimerrors.ErrInvalidValue(`"members.value" must reference a User or Group in this provider`)
}

func errSCIMTooManyRequests() error {
	return scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached")
}
