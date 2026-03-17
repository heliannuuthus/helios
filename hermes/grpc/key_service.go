package grpc

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
)

type keyServiceServer struct {
	hermesv1.UnimplementedKeyServiceServer
	svc *hermes.Service
}

func NewKeyServiceServer(svc *hermes.Service) hermesv1.KeyServiceServer {
	return &keyServiceServer{svc: svc}
}

func (s *keyServiceServer) GetKeys(ctx context.Context, req *hermesv1.GetKeysRequest) (*hermesv1.KeySet, error) {
	var keys [][]byte
	var err error

	switch req.GetOwnerType() {
	case "domain":
		dwk, e := s.svc.GetDomainWithKey(ctx, req.GetOwnerId())
		if e != nil {
			return nil, toStatus(e)
		}
		return &hermesv1.KeySet{Main: dwk.Main, Keys: dwk.Keys}, nil
	case "application":
		keys, err = s.svc.GetApplicationKeys(ctx, req.GetOwnerId())
	case "service":
		keys, err = s.svc.GetServiceKeys(ctx, req.GetOwnerId())
	default:
		return nil, toStatus(fmt.Errorf("unknown owner_type: %s", req.GetOwnerType()))
	}
	if err != nil {
		return nil, toStatus(err)
	}

	result := &hermesv1.KeySet{Keys: keys}
	if len(keys) > 0 {
		result.Main = keys[0]
	}
	return result, nil
}

func (s *keyServiceServer) RotateKey(ctx context.Context, req *hermesv1.RotateKeyRequest) (*emptypb.Empty, error) {
	window := time.Duration(req.GetWindowSeconds()) * time.Second
	if err := s.svc.RotateKey(ctx, req.GetOwnerType(), req.GetOwnerId(), window); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}
