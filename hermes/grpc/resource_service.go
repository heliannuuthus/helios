package grpc

import (
	"context"
	"time"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type resourceServiceServer struct {
	hermesv1.UnimplementedResourceServiceServer
	svc *hermes.Service
}

func NewResourceServiceServer(svc *hermes.Service) hermesv1.ResourceServiceServer {
	return &resourceServiceServer{svc: svc}
}

func (s *resourceServiceServer) CreateService(ctx context.Context, req *hermesv1.CreateServiceRequest) (*hermesv1.Service, error) {
	createReq := &hermes.ServiceCreateRequest{
		ServiceID:   req.GetServiceId(),
		DomainID:    req.GetDomainId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		LogoURL:     req.LogoUrl,
	}
	if req.AccessTokenExpiresIn != nil {
		v := uint(*req.AccessTokenExpiresIn)
		createReq.AccessTokenExpiresIn = &v
	}

	svc, err := s.svc.CreateService(ctx, createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return serviceToProto(svc), nil
}

func (s *resourceServiceServer) GetService(ctx context.Context, req *hermesv1.GetServiceRequest) (*hermesv1.Service, error) {
	svc, err := s.svc.GetService(ctx, req.GetServiceId())
	if err != nil {
		return nil, toStatus(err)
	}
	return serviceToProto(svc), nil
}

func (s *resourceServiceServer) ListServices(ctx context.Context, req *hermesv1.ListServicesRequest) (*hermesv1.ServiceList, error) {
	listReq := &hermes.ListRequest{Filter: req.GetFilter()}
	if p := req.GetPagination(); p != nil {
		listReq.Pagination = pagination.Pagination{Token: p.GetCursor(), Size: int(p.GetLimit())}
	}

	items, err := s.svc.ListServices(ctx, req.GetDomainId(), listReq)
	if err != nil {
		return nil, toStatus(err)
	}

	out := make([]*hermesv1.Service, 0, len(items.Items))
	for i := range items.Items {
		out = append(out, serviceToProto(&items.Items[i]))
	}
	return &hermesv1.ServiceList{Services: out, NextCursor: items.Next}, nil
}

func (s *resourceServiceServer) UpdateService(ctx context.Context, req *hermesv1.UpdateServiceRequest) (*hermesv1.Service, error) {
	updateReq := &hermes.ServiceUpdateRequest{
		Name:        optionalFromPtr(req.Name),
		Description: optionalFromPtr(req.Description),
		LogoURL:     optionalFromPtr(req.LogoUrl),
	}
	if req.AccessTokenExpiresIn != nil {
		updateReq.AccessTokenExpiresIn = optionalUintFromPtr32(req.AccessTokenExpiresIn)
	}

	if err := s.svc.UpdateService(ctx, req.GetServiceId(), updateReq); err != nil {
		return nil, toStatus(err)
	}

	svc, err := s.svc.GetService(ctx, req.GetServiceId())
	if err != nil {
		return nil, toStatus(err)
	}
	return serviceToProto(svc), nil
}

func (s *resourceServiceServer) DeleteService(ctx context.Context, req *hermesv1.DeleteServiceRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteService(ctx, req.GetServiceId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *resourceServiceServer) GetServiceChallengeSetting(ctx context.Context, req *hermesv1.GetServiceChallengeSettingRequest) (*hermesv1.ServiceChallengeSetting, error) {
	cfg, err := s.svc.GetServiceChallengeSetting(ctx, req.GetServiceId(), req.GetType())
	if err != nil {
		return nil, toStatus(err)
	}
	return challengeSettingToProto(cfg), nil
}

func (s *resourceServiceServer) GetServiceApplicationRelations(ctx context.Context, req *hermesv1.GetServiceRequest) (*hermesv1.ApplicationServiceRelationList, error) {
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

func (s *resourceServiceServer) CreateRelationship(ctx context.Context, req *hermesv1.CreateRelationshipRequest) (*hermesv1.Relationship, error) {
	createReq := &hermes.RelationshipCreateRequest{
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
	deleteReq := &hermes.RelationshipDeleteRequest{
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
	updateReq := &hermes.RelationshipUpdateRequest{
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
	listReq := &hermes.ListRequest{Filter: req.GetFilter()}
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

func (s *resourceServiceServer) ListAppServiceRelationships(ctx context.Context, req *hermesv1.ListAppServiceRelationshipsRequest) (*hermesv1.RelationshipList, error) {
	listReq := &hermes.ListRequest{Filter: req.GetFilter()}
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
	createReq := &hermes.AppServiceRelationshipCreateRequest{
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
	updateReq := &hermes.AppServiceRelationshipUpdateRequest{
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

func (s *resourceServiceServer) CreateGroup(ctx context.Context, req *hermesv1.CreateGroupRequest) (*hermesv1.Group, error) {
	createReq := &hermes.GroupCreateRequest{
		GroupID:     req.GetGroupId(),
		ServiceID:   req.GetServiceId(),
		Name:        req.GetName(),
		Description: req.Description,
	}

	g, err := s.svc.CreateGroup(ctx, createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return groupToProto(g), nil
}

func (s *resourceServiceServer) GetGroup(ctx context.Context, req *hermesv1.GetGroupRequest) (*hermesv1.Group, error) {
	g, err := s.svc.GetGroup(ctx, req.GetGroupId())
	if err != nil {
		return nil, toStatus(err)
	}
	return groupToProto(g), nil
}

func (s *resourceServiceServer) ListGroups(ctx context.Context, req *hermesv1.ListGroupsRequest) (*hermesv1.GroupList, error) {
	listReq := &hermes.ListRequest{Filter: req.GetFilter()}
	if p := req.GetPagination(); p != nil {
		listReq.Pagination = pagination.Pagination{Token: p.GetCursor(), Size: int(p.GetLimit())}
	}

	items, err := s.svc.ListGroups(ctx, listReq)
	if err != nil {
		return nil, toStatus(err)
	}

	out := make([]*hermesv1.Group, 0, len(items.Items))
	for i := range items.Items {
		out = append(out, groupToProto(&items.Items[i]))
	}
	return &hermesv1.GroupList{Groups: out, NextCursor: items.Next}, nil
}

func (s *resourceServiceServer) UpdateGroup(ctx context.Context, req *hermesv1.UpdateGroupRequest) (*hermesv1.Group, error) {
	updateReq := &hermes.GroupUpdateRequest{
		Name:        optionalFromPtr(req.Name),
		Description: optionalFromPtr(req.Description),
	}
	if err := s.svc.UpdateGroup(ctx, req.GetGroupId(), updateReq); err != nil {
		return nil, toStatus(err)
	}
	g, err := s.svc.GetGroup(ctx, req.GetGroupId())
	if err != nil {
		return nil, toStatus(err)
	}
	return groupToProto(g), nil
}

func (s *resourceServiceServer) DeleteGroup(ctx context.Context, req *hermesv1.GetGroupRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteGroup(ctx, req.GetGroupId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *resourceServiceServer) SetGroupMembers(ctx context.Context, req *hermesv1.SetGroupMembersRequest) (*emptypb.Empty, error) {
	memberReq := &hermes.GroupMemberRequest{
		GroupID: req.GetGroupId(),
		UserIDs: req.GetUserIds(),
	}
	if err := s.svc.SetGroupMembers(ctx, memberReq); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *resourceServiceServer) GetGroupMembers(ctx context.Context, req *hermesv1.GetGroupRequest) (*hermesv1.StringList, error) {
	members, err := s.svc.GetGroupMembers(ctx, req.GetGroupId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.StringList{Values: members}, nil
}

// ==================== conversion helpers ====================

func serviceToProto(svc *models.Service) *hermesv1.Service {
	pb := &hermesv1.Service{
		Id:                    uint32(svc.ID),
		DomainId:              svc.DomainID,
		ServiceId:             svc.ServiceID,
		Name:                  svc.Name,
		Description:           svc.Description,
		LogoUrl:               svc.LogoURL,
		AccessTokenExpiresIn:  uint32(svc.AccessTokenExpiresIn),
		RequiredIdentityTypes: svc.GetRequiredIdentities(),
		CreatedAt:             timestamppb.New(svc.CreatedAt),
		UpdatedAt:             timestamppb.New(svc.UpdatedAt),
	}

	if len(svc.ChallengeSettings) > 0 {
		settings := make([]*hermesv1.ServiceChallengeSetting, 0, len(svc.ChallengeSettings))
		for i := range svc.ChallengeSettings {
			settings = append(settings, challengeSettingToProto(&svc.ChallengeSettings[i]))
		}
		pb.ChallengeSettings = settings
	}

	return pb
}

func challengeSettingToProto(cfg *models.ServiceChallengeSetting) *hermesv1.ServiceChallengeSetting {
	limits := make(map[string]int32, len(cfg.Limits))
	for k, v := range cfg.Limits {
		limits[k] = int32(v)
	}
	return &hermesv1.ServiceChallengeSetting{
		Id:        uint32(cfg.ID),
		ServiceId: cfg.ServiceID,
		Type:      cfg.Type,
		ExpiresIn: uint32(cfg.ExpiresIn),
		Limits:    limits,
		CreatedAt: timestamppb.New(cfg.CreatedAt),
		UpdatedAt: timestamppb.New(cfg.UpdatedAt),
	}
}

func relationshipToProto(r *models.Relationship) *hermesv1.Relationship {
	pb := &hermesv1.Relationship{
		Id:          uint32(r.ID),
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

func groupToProto(g *models.Group) *hermesv1.Group {
	return &hermesv1.Group{
		Id:          uint32(g.ID),
		GroupId:     g.GroupID,
		ServiceId:   g.ServiceID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   timestamppb.New(g.CreatedAt),
		UpdatedAt:   timestamppb.New(g.UpdatedAt),
	}
}
