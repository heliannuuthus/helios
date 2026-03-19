package grpc

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
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

func (s *keyServiceServer) RotateKey(ctx context.Context, req *hermesv1.RotateKeyRequest) (*emptypb.Empty, error) {
	window := time.Duration(req.GetWindowSeconds()) * time.Second
	if err := s.svc.RotateKey(ctx, req.GetOwnerType(), req.GetOwnerId(), window); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ==================== IDP Key ====================

func (s *keyServiceServer) ListIDPKeys(ctx context.Context, _ *emptypb.Empty) (*hermesv1.IDPKeyList, error) {
	keys, err := s.svc.GetIDPKeys(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.IDPKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, idpKeyToProto(k))
	}
	return &hermesv1.IDPKeyList{Keys: out}, nil
}

func (s *keyServiceServer) GetIDPKey(ctx context.Context, req *hermesv1.GetIDPKeyRequest) (*hermesv1.IDPKey, error) {
	k, err := s.svc.GetIDPKey(ctx, req.GetIdpType(), req.GetTAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return idpKeyToProto(k), nil
}

func (s *keyServiceServer) CreateIDPKey(ctx context.Context, req *hermesv1.CreateIDPKeyRequest) (*hermesv1.IDPKey, error) {
	createReq := &dto.IDPKeyCreateRequest{
		IDPType: req.GetIdpType(),
		TAppID:  req.GetTAppId(),
		TSecret: req.GetTSecret(),
	}
	k, err := s.svc.CreateIDPKey(ctx, createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return idpKeyToProto(k), nil
}

func (s *keyServiceServer) UpdateIDPKey(ctx context.Context, req *hermesv1.UpdateIDPKeyRequest) (*emptypb.Empty, error) {
	updateReq := &dto.IDPKeyUpdateRequest{
		TSecret: optionalFromPtr(req.TSecret),
	}
	if err := s.svc.UpdateIDPKey(ctx, req.GetIdpType(), req.GetTAppId(), updateReq); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *keyServiceServer) DeleteIDPKey(ctx context.Context, req *hermesv1.DeleteIDPKeyRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteIDPKey(ctx, req.GetIdpType(), req.GetTAppId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
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

func idpKeyToProto(k *models.IDPKey) *hermesv1.IDPKey {
	return &hermesv1.IDPKey{
		Id:        safeUint32(k.ID),
		IdpType:   k.IDPType,
		TAppId:    k.TAppID,
		CreatedAt: timestamppb.New(k.CreatedAt),
		UpdatedAt: timestamppb.New(k.UpdatedAt),
	}
}
