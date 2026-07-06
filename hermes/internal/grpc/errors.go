package grpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

func toStatus(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}
	return status.Error(codes.Internal, err.Error())
}
