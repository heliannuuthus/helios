package grpc

import (
	"context"
	"fmt"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
)

type keyServiceServer struct {
	hermesv1.UnimplementedKeyServiceServer
	svc *hermes.KeyService
}

func NewKeyServiceServer(svc *hermes.KeyService) hermesv1.KeyServiceServer {
	return &keyServiceServer{svc: svc}
}

func (s *keyServiceServer) GetKeys(ctx context.Context, req *hermesv1.GetKeysRequest) (*hermesv1.KeySet, error) {
	var keys [][]byte
	var err error

	switch req.GetOwnerType() {
	case "domain":
		keys, err = s.svc.GetDomainKeys(ctx, req.GetOwnerId())
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

func (s *keyServiceServer) ResolveIDPKey(ctx context.Context, req *hermesv1.ResolveIDPKeyRequest) (*hermesv1.ResolveIDPKeyResponse, error) {
	tAppID, tSecret, err := s.svc.ResolveIDPKey(ctx, req.GetAppId(), req.GetIdpType())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.ResolveIDPKeyResponse{
		TAppId:  tAppID,
		TSecret: tSecret,
	}, nil
}
