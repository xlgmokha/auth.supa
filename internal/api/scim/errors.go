package scim

import (
	"errors"
	"net/http"

	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
)

func Error(err error) error {
	switch {
	case models.IsNotFoundError(err):
		return errNotFound()
	case errors.Is(err, models.ErrSCIMStale):
		return errStale()
	case errors.Is(err, models.ErrSCIMGroupConflict):
		return scimerrors.ErrUniqueness(`"externalId" must be unique`)
	case errors.Is(err, models.ErrSCIMGroupMemberNotFound):
		return errMemberNotFound()
	case errors.Is(err, models.ErrSCIMGroupCycle):
		return scimerrors.ErrInvalidValue(`"members" must not create a group cycle`)
	case errors.Is(err, models.ErrSCIMUserConflict):
		return scimerrors.ErrUniqueness(`"userName" and "externalId" must be unique`)
	}
	return err
}

func ErrUniqueness(detail string) error {
	return scimerrors.ErrUniqueness(detail)
}

func ErrStatus(status int, detail string) error {
	return scimerrors.NewError(status, "", detail)
}

func errNotFound() error {
	return scimerrors.ErrNotFound("resource not found")
}

func errStale() error {
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func errMemberNotFound() error {
	return scimerrors.ErrInvalidValue(`"members.value" must reference a User or Group in this provider`)
}

func errTooManyRequests() error {
	return scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached")
}

func SendTooManyRequests(w http.ResponseWriter) error {
	return protocol.SendError(w, errTooManyRequests())
}
