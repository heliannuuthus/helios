package grpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
)

type resourceServiceServer struct {
	hermesv1.UnimplementedResourceServiceServer
	svc *hermes.ResourceService
}

func NewResourceServiceServer(svc *hermes.ResourceService) hermesv1.ResourceServiceServer {
	return &resourceServiceServer{svc: svc}
}

func (s *resourceServiceServer) GetApplicationServiceRelations(ctx context.Context, req *hermesv1.GetApplicationServiceRelationsRequest) (*hermesv1.ApplicationServiceRelationList, error) {
	rels, err := s.svc.FindApplicationRelations(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.ApplicationServiceRelation, 0, len(rels))
	for i := range rels {
		out = append(out, appServiceRelationToProto(&rels[i]))
	}
	return &hermesv1.ApplicationServiceRelationList{Relations: out}, nil
}

func (s *resourceServiceServer) FindRelationships(ctx context.Context, req *hermesv1.FindRelationshipsRequest) (*hermesv1.Relationships, error) {
	rels, err := s.svc.FindRelationships(ctx, req.GetServiceId(), req.GetSubjectType(), req.GetSubjectId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.Relationship, 0, len(rels))
	for i := range rels {
		out = append(out, relationshipToProto(&rels[i]))
	}
	return &hermesv1.Relationships{Items: out}, nil
}

// ==================== conversion helpers ====================

func appServiceRelationToProto(r *models.ApplicationServiceRelation) *hermesv1.ApplicationServiceRelation {
	return &hermesv1.ApplicationServiceRelation{
		Id:        safeUint32(r.ID),
		AppId:     r.AppID,
		ServiceId: r.ServiceID,
		Relation:  r.Relation,
		CreatedAt: timestamppb.New(r.CreatedAt),
	}
}

func relationshipToProto(r *models.Relationship) *hermesv1.Relationship {
	pb := &hermesv1.Relationship{
		Id:          safeUint32(r.ID),
		ServiceId:   r.ServiceID,
		SubjectType: r.SubjectType,
		SubjectId:   r.SubjectID,
		Relation:    r.Relation,
		ObjectType:  r.ObjectType,
		ObjectId:    r.ObjectID,
		CreatedAt:   timestamppb.New(r.CreatedAt),
	}
	if r.ExpiresAt != nil {
		pb.ExpiresAt = timestamppb.New(*r.ExpiresAt)
	}
	return pb
}
