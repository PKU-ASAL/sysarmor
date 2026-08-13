package failure

import "errors"

type Kind string

const (
	InvalidArgument     Kind = "InvalidArgument"
	Unauthenticated     Kind = "Unauthenticated"
	PermissionDenied    Kind = "PermissionDenied"
	NotFound            Kind = "NotFound"
	Conflict            Kind = "Conflict"
	FailedPrecondition  Kind = "FailedPrecondition"
	ResourceExhausted   Kind = "ResourceExhausted"
	RetryableDependency Kind = "RetryableDependency"
	Internal            Kind = "Internal"
)

type Error struct {
	kind    Kind
	message string
}

func New(kind Kind, message string) *Error {
	return &Error{kind: kind, message: message}
}

func (e *Error) Error() string { return e.message }

func (e *Error) Kind() Kind { return e.kind }

func KindOf(err error) Kind {
	if err == nil {
		return ""
	}
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Kind()
	}
	return Internal
}
