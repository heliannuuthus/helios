package grpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

type resourceServiceServer struct {
	hermesv1.UnimplementedResourceServiceServer
	svc *hermes.Service
}

func NewResourceServiceServer(svc *hermes.Service) hermesv1.ResourceServiceServer {
	return &resourceServiceServer{svc: svc}
}

// ==================== Application-Service Relation ====================

func (s *resourceServiceServer) SetApplicationServiceRelations(ctx context.Context, req *hermesv1.SetApplicationServiceRelationsRequest) (*emptypb.Empty, error) {
	svcReq := &dto.ApplicationServiceRelationRequest{
		AppID:     req.GetAppId(),
		ServiceID: req.GetServiceId(),
		Relations: req.GetRelations(),
	}
	if err := s.svc.SetApplicationServiceRelations(ctx, svcReq); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *resourceServiceServer) GetApplicationServiceRelations(ctx context.Context, req *hermesv1.GetApplicationServiceRelationsRequest) (*hermesv1.ApplicationServiceRelationList, error) {
	rels, err := s.svc.GetApplicationServiceRelations(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.ApplicationServiceRelation, 0, len(rels))
	for i := range rels {
		out = append(out, appServiceRelationToProto(&rels[i]))
	}
	return &hermesv1.ApplicationServiceRelationList{Relations: out}, nil
}

func (s *resourceServiceServer) GetServiceAppRelations(ctx context.Context, req *hermesv1.GetServiceAppRelationsRequest) (*hermesv1.StringList, error) {
	rels, err := s.svc.GetServiceAppRelations(ctx, req.GetServiceId(), req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.StringList{Values: rels}, nil
}

func (s *resourceServiceServer) GetServiceApplicationRelations(ctx context.Context, req *hermesv1.GetServiceApplicationRelationsRequest) (*hermesv1.ApplicationServiceRelationList, error) {
	rels, err := s.svc.GetServiceApplicationRelations(ctx, req.GetServiceId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.ApplicationServiceRelation, 0, len(rels))
	for i := range rels {
		out = append(out, appServiceRelationToProto(&rels[i]))
	}
	return &hermesv1.ApplicationServiceRelationList{Relations: out}, nil
}

// ==================== Relationship ====================

func (s *resourceServiceServer) CreateRelationship(ctx context.Context, req *hermesv1.CreateRelationshipRequest) (*hermesv1.Relationship, error) {
	createReq := &dto.RelationshipCreateRequest{
		ServiceID:   req.GetServiceId(),
		SubjectType: req.GetSubjectType(),
		SubjectID:   req.GetSubjectId(),
		Relation:    req.GetRelation(),
		ObjectType:  req.GetObjectType(),
		ObjectID:    req.GetObjectId(),
	}
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime().Format(time.RFC3339)
		createReq.ExpiresAt = &t
	}

	rel, err := s.svc.CreateRelationship(ctx, createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return relationshipToProto(rel), nil
}

func (s *resourceServiceServer) DeleteRelationship(ctx context.Context, req *hermesv1.DeleteRelationshipRequest) (*emptypb.Empty, error) {
	deleteReq := &dto.RelationshipDeleteRequest{
		ServiceID:   req.GetServiceId(),
		SubjectType: req.GetSubjectType(),
		SubjectID:   req.GetSubjectId(),
		Relation:    req.GetRelation(),
		ObjectType:  req.GetObjectType(),
		ObjectID:    req.GetObjectId(),
	}
	if err := s.svc.DeleteRelationship(ctx, deleteReq); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *resourceServiceServer) UpdateRelationship(ctx context.Context, req *hermesv1.UpdateRelationshipRequest) (*hermesv1.Relationship, error) {
	updateReq := &dto.RelationshipUpdateRequest{
		ServiceID:   req.GetServiceId(),
		SubjectType: req.GetSubjectType(),
		SubjectID:   req.GetSubjectId(),
		Relation:    req.GetRelation(),
		ObjectType:  req.GetObjectType(),
		ObjectID:    req.GetObjectId(),
		NewRelation: optionalFromPtr(req.NewRelation),
	}

	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		if t.IsZero() {
			updateReq.ExpiresAt = patch.Null[string]()
		} else {
			updateReq.ExpiresAt = patch.Set(t.Format(time.RFC3339))
		}
	}

	rel, err := s.svc.UpdateRelationship(ctx, updateReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return relationshipToProto(rel), nil
}

func (s *resourceServiceServer) ListRelationships(ctx context.Context, req *hermesv1.ListRelationshipsRequest) (*hermesv1.RelationshipList, error) {
	listReq := &dto.ListRequest{Filter: req.GetFilter()}
	if p := req.GetPagination(); p != nil {
		listReq.Pagination = pagination.Pagination{Token: p.GetCursor(), Size: int(p.GetLimit())}
	}

	items, err := s.svc.ListRelationships(ctx, listReq)
	if err != nil {
		return nil, toStatus(err)
	}

	out := make([]*hermesv1.Relationship, 0, len(items.Items))
	for i := range items.Items {
		out = append(out, relationshipToProto(&items.Items[i]))
	}
	return &hermesv1.RelationshipList{Relationships: out, NextCursor: items.Next}, nil
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

// ==================== AppService Relationship ====================

func (s *resourceServiceServer) ListAppServiceRelationships(ctx context.Context, req *hermesv1.ListAppServiceRelationshipsRequest) (*hermesv1.RelationshipList, error) {
	listReq := &dto.ListRequest{Filter: req.GetFilter()}
	if p := req.GetPagination(); p != nil {
		listReq.Pagination = pagination.Pagination{Token: p.GetCursor(), Size: int(p.GetLimit())}
	}

	items, err := s.svc.ListAppServiceRelationships(ctx, req.GetAppId(), req.GetServiceId(), listReq)
	if err != nil {
		return nil, toStatus(err)
	}

	out := make([]*hermesv1.Relationship, 0, len(items.Items))
	for i := range items.Items {
		out = append(out, relationshipToProto(&items.Items[i]))
	}
	return &hermesv1.RelationshipList{Relationships: out, NextCursor: items.Next}, nil
}

func (s *resourceServiceServer) CreateAppServiceRelationship(ctx context.Context, req *hermesv1.CreateAppServiceRelationshipRequest) (*hermesv1.Relationship, error) {
	createReq := &dto.AppServiceRelationshipCreateRequest{
		SubjectType: req.GetSubjectType(),
		SubjectID:   req.GetSubjectId(),
		Relation:    req.GetRelation(),
		ObjectType:  req.GetObjectType(),
		ObjectID:    req.GetObjectId(),
	}
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime().Format(time.RFC3339)
		createReq.ExpiresAt = &t
	}

	rel, err := s.svc.CreateAppServiceRelationship(ctx, req.GetAppId(), req.GetServiceId(), createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return relationshipToProto(rel), nil
}

func (s *resourceServiceServer) UpdateAppServiceRelationship(ctx context.Context, req *hermesv1.UpdateAppServiceRelationshipRequest) (*hermesv1.Relationship, error) {
	updateReq := &dto.AppServiceRelationshipUpdateRequest{
		NewRelation: optionalFromPtr(req.NewRelation),
	}

	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		if t.IsZero() {
			updateReq.ExpiresAt = patch.Null[string]()
		} else {
			updateReq.ExpiresAt = patch.Set(t.Format(time.RFC3339))
		}
	}

	rel, err := s.svc.UpdateAppServiceRelationship(ctx, req.GetAppId(), req.GetServiceId(), uint(req.GetRelationshipId()), updateReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return relationshipToProto(rel), nil
}

func (s *resourceServiceServer) DeleteAppServiceRelationship(ctx context.Context, req *hermesv1.DeleteAppServiceRelationshipRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteAppServiceRelationship(ctx, req.GetAppId(), req.GetServiceId(), uint(req.GetRelationshipId())); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
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
