package grpc

import (
	"context"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type appServiceServer struct {
	hermesv1.UnimplementedAppServiceServer
	svc *hermes.Service
}

func NewAppServiceServer(svc *hermes.Service) hermesv1.AppServiceServer {
	return &appServiceServer{svc: svc}
}

func (s *appServiceServer) GetDomain(ctx context.Context, req *hermesv1.GetDomainRequest) (*hermesv1.Domain, error) {
	d, err := s.svc.GetDomain(ctx, req.GetDomainId())
	if err != nil {
		return nil, toStatus(err)
	}
	return domainToProto(d), nil
}

func (s *appServiceServer) ListDomains(ctx context.Context, _ *emptypb.Empty) (*hermesv1.DomainList, error) {
	domains, err := s.svc.ListDomains(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.Domain, 0, len(domains))
	for i := range domains {
		out = append(out, domainToProto(&domains[i]))
	}
	return &hermesv1.DomainList{Domains: out}, nil
}

func (s *appServiceServer) UpdateDomain(ctx context.Context, req *hermesv1.UpdateDomainRequest) (*hermesv1.Domain, error) {
	updateReq := &hermes.DomainUpdateRequest{
		Name:        optionalFromPtr(req.Name),
		Description: optionalFromPtr(req.Description),
	}
	d, err := s.svc.UpdateDomain(ctx, req.GetDomainId(), updateReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return domainToProto(d), nil
}

func (s *appServiceServer) GetDomainAllowedIDPs(ctx context.Context, req *hermesv1.GetDomainRequest) (*hermesv1.StringList, error) {
	idps, err := s.svc.GetDomainAllowedIDPs(ctx, req.GetDomainId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.StringList{Values: idps}, nil
}

func (s *appServiceServer) CreateApplication(ctx context.Context, req *hermesv1.CreateApplicationRequest) (*hermesv1.Application, error) {
	createReq := &hermes.ApplicationCreateRequest{
		DomainID:            req.GetDomainId(),
		Name:                req.GetName(),
		Description:         req.GetDescription(),
		AllowedRedirectURIs: req.GetAllowedRedirectUris(),
		AllowedOrigins:      req.GetAllowedOrigins(),
		AllowedLogoutURIs:   req.GetAllowedLogoutUris(),
		NeedKey:             req.GetNeedKey(),
	}
	if req.AppId != nil {
		createReq.AppID = *req.AppId
	}
	if req.IdTokenExpiresIn != nil {
		v := uint(*req.IdTokenExpiresIn)
		createReq.IDTokenExpiresIn = &v
	}
	if req.RefreshTokenExpiresIn != nil {
		v := uint(*req.RefreshTokenExpiresIn)
		createReq.RefreshTokenExpiresIn = &v
	}
	if req.RefreshTokenAbsoluteExpiresIn != nil {
		v := uint(*req.RefreshTokenAbsoluteExpiresIn)
		createReq.RefreshTokenAbsoluteExpiresIn = &v
	}

	app, err := s.svc.CreateApplication(ctx, createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return applicationToProto(app), nil
}

func (s *appServiceServer) GetApplication(ctx context.Context, req *hermesv1.GetApplicationRequest) (*hermesv1.Application, error) {
	app, err := s.svc.GetApplication(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return applicationToProto(app), nil
}

func (s *appServiceServer) ListApplications(ctx context.Context, req *hermesv1.ListApplicationsRequest) (*hermesv1.ApplicationList, error) {
	listReq := &hermes.ListRequest{
		Filter: req.GetFilter(),
	}
	if p := req.GetPagination(); p != nil {
		listReq.Pagination = pagination.Pagination{Token: p.GetCursor(), Size: int(p.GetLimit())}
	}

	items, err := s.svc.ListApplications(ctx, req.GetDomainId(), listReq)
	if err != nil {
		return nil, toStatus(err)
	}

	apps := make([]*hermesv1.Application, 0, len(items.Items))
	for i := range items.Items {
		apps = append(apps, applicationToProto(&items.Items[i]))
	}
	return &hermesv1.ApplicationList{Applications: apps, NextCursor: items.Next}, nil
}

func (s *appServiceServer) UpdateApplication(ctx context.Context, req *hermesv1.UpdateApplicationRequest) (*hermesv1.Application, error) {
	updateReq := &hermes.ApplicationUpdateRequest{
		Name:        optionalFromPtr(req.Name),
		Description: optionalFromPtr(req.Description),
		LogoURL:     optionalFromPtr(req.LogoUrl),
	}

	if req.AllowedRedirectUris != nil {
		updateReq.AllowedRedirectURIs = optionalStringListFromProto(req.AllowedRedirectUris)
	}
	if req.AllowedOrigins != nil {
		updateReq.AllowedOrigins = optionalStringListFromProto(req.AllowedOrigins)
	}
	if req.AllowedLogoutUris != nil {
		updateReq.AllowedLogoutURIs = optionalStringListFromProto(req.AllowedLogoutUris)
	}

	if req.IdTokenExpiresIn != nil {
		updateReq.IDTokenExpiresIn = optionalUintFromPtr32(req.IdTokenExpiresIn)
	}
	if req.RefreshTokenExpiresIn != nil {
		updateReq.RefreshTokenExpiresIn = optionalUintFromPtr32(req.RefreshTokenExpiresIn)
	}
	if req.RefreshTokenAbsoluteExpiresIn != nil {
		updateReq.RefreshTokenAbsoluteExpiresIn = optionalUintFromPtr32(req.RefreshTokenAbsoluteExpiresIn)
	}

	if err := s.svc.UpdateApplication(ctx, req.GetAppId(), updateReq); err != nil {
		return nil, toStatus(err)
	}

	app, err := s.svc.GetApplication(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return applicationToProto(app), nil
}

func (s *appServiceServer) GetApplicationIDPConfigs(ctx context.Context, req *hermesv1.GetApplicationRequest) (*hermesv1.ApplicationIDPConfigList, error) {
	configs, err := s.svc.GetApplicationIDPConfigs(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.ApplicationIDPConfig, 0, len(configs))
	for _, cfg := range configs {
		out = append(out, idpConfigToProto(cfg))
	}
	return &hermesv1.ApplicationIDPConfigList{Configs: out}, nil
}

func (s *appServiceServer) CreateApplicationIDPConfig(ctx context.Context, req *hermesv1.CreateApplicationIDPConfigRequest) (*hermesv1.ApplicationIDPConfig, error) {
	createReq := &hermes.ApplicationIDPConfigCreateRequest{
		Type:     req.GetType(),
		Priority: int(req.GetPriority()),
		Strategy: req.Strategy,
		Delegate: req.Delegate,
		Require:  req.Require,
	}
	cfg, err := s.svc.CreateApplicationIDPConfig(ctx, req.GetAppId(), createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return idpConfigToProto(cfg), nil
}

func (s *appServiceServer) UpdateApplicationIDPConfig(ctx context.Context, req *hermesv1.UpdateApplicationIDPConfigRequest) (*hermesv1.ApplicationIDPConfig, error) {
	updateReq := &hermes.ApplicationIDPConfigUpdateRequest{
		Strategy: optionalFromPtr(req.Strategy),
		Delegate: optionalFromPtr(req.Delegate),
		Require:  optionalFromPtr(req.Require),
	}
	if req.Priority != nil {
		updateReq.Priority = optionalIntFromPtr32(req.Priority)
	}

	if err := s.svc.UpdateApplicationIDPConfig(ctx, req.GetAppId(), req.GetType(), updateReq); err != nil {
		return nil, toStatus(err)
	}

	configs, err := s.svc.GetApplicationIDPConfigs(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	for _, cfg := range configs {
		if cfg.Type == req.GetType() {
			return idpConfigToProto(cfg), nil
		}
	}
	return nil, toStatus(err)
}

func (s *appServiceServer) DeleteApplicationIDPConfig(ctx context.Context, req *hermesv1.DeleteApplicationIDPConfigRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteApplicationIDPConfig(ctx, req.GetAppId(), req.GetType()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *appServiceServer) SetApplicationServiceRelations(ctx context.Context, req *hermesv1.SetApplicationServiceRelationsRequest) (*emptypb.Empty, error) {
	svcReq := &hermes.ApplicationServiceRelationRequest{
		AppID:     req.GetAppId(),
		ServiceID: req.GetServiceId(),
		Relations: req.GetRelations(),
	}
	if err := s.svc.SetApplicationServiceRelations(ctx, svcReq); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *appServiceServer) GetApplicationServiceRelations(ctx context.Context, req *hermesv1.GetApplicationRequest) (*hermesv1.ApplicationServiceRelationList, error) {
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

func (s *appServiceServer) GetServiceAppRelations(ctx context.Context, req *hermesv1.GetServiceAppRelationsRequest) (*hermesv1.StringList, error) {
	rels, err := s.svc.GetServiceAppRelations(ctx, req.GetServiceId(), req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.StringList{Values: rels}, nil
}

// ==================== conversion helpers ====================

func domainToProto(d *models.Domain) *hermesv1.Domain {
	pb := &hermesv1.Domain{
		DomainId:    d.DomainID,
		Name:        d.Name,
		Description: d.Description,
		AllowedIdps: d.AllowedIDPs,
	}
	return pb
}

func applicationToProto(a *models.Application) *hermesv1.Application {
	pb := &hermesv1.Application{
		Id:                            uint32(a.ID),
		DomainId:                      a.DomainID,
		AppId:                         a.AppID,
		Name:                          a.Name,
		Description:                   a.Description,
		LogoUrl:                       a.LogoURL,
		AllowedRedirectUris:           a.GetAllowedRedirectURIs(),
		AllowedOrigins:                a.GetAllowedOrigins(),
		AllowedLogoutUris:             a.GetAllowedLogoutURIs(),
		IdTokenExpiresIn:              uint32(a.IDTokenExpiresIn),
		RefreshTokenExpiresIn:         uint32(a.RefreshTokenExpiresIn),
		RefreshTokenAbsoluteExpiresIn: uint32(a.RefreshTokenAbsoluteExpiresIn),
		CreatedAt:                     timestamppb.New(a.CreatedAt),
		UpdatedAt:                     timestamppb.New(a.UpdatedAt),
	}
	return pb
}

func idpConfigToProto(cfg *models.ApplicationIDPConfig) *hermesv1.ApplicationIDPConfig {
	return &hermesv1.ApplicationIDPConfig{
		Id:        uint32(cfg.ID),
		AppId:     cfg.AppID,
		Type:      cfg.Type,
		Priority:  int32(cfg.Priority),
		Strategy:  cfg.Strategy,
		Delegate:  cfg.Delegate,
		Require:   cfg.Require,
		CreatedAt: timestamppb.New(cfg.CreatedAt),
		UpdatedAt: timestamppb.New(cfg.UpdatedAt),
	}
}

func appServiceRelationToProto(r *models.ApplicationServiceRelation) *hermesv1.ApplicationServiceRelation {
	return &hermesv1.ApplicationServiceRelation{
		Id:        uint32(r.ID),
		AppId:     r.AppID,
		ServiceId: r.ServiceID,
		Relation:  r.Relation,
		CreatedAt: timestamppb.New(r.CreatedAt),
	}
}

func optionalFromPtr[T any](p *T) patch.Optional[T] {
	if p == nil {
		return patch.Optional[T]{}
	}
	return patch.Set(*p)
}

func optionalStringListFromProto(osl *hermesv1.OptionalStringList) patch.Optional[[]string] {
	if !osl.GetPresent() {
		return patch.Optional[[]string]{}
	}
	if len(osl.GetValues()) == 0 {
		return patch.Null[[]string]()
	}
	return patch.Set(osl.GetValues())
}

func optionalUintFromPtr32(p *uint32) patch.Optional[uint] {
	if p == nil {
		return patch.Optional[uint]{}
	}
	return patch.Set(uint(*p))
}

func optionalIntFromPtr32(p *int32) patch.Optional[int] {
	if p == nil {
		return patch.Optional[int]{}
	}
	return patch.Set(int(*p))
}
