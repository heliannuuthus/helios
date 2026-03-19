package grpc

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

type provisionServiceServer struct {
	hermesv1.UnimplementedProvisionServiceServer
	svc *hermes.Service
}

func NewProvisionServiceServer(svc *hermes.Service) hermesv1.ProvisionServiceServer {
	return &provisionServiceServer{svc: svc}
}

// ==================== Domain ====================

func (s *provisionServiceServer) GetDomain(ctx context.Context, req *hermesv1.GetDomainRequest) (*hermesv1.Domain, error) {
	d, err := s.svc.GetDomain(ctx, req.GetDomainId())
	if err != nil {
		return nil, toStatus(err)
	}
	return domainToProto(d), nil
}

func (s *provisionServiceServer) ListDomains(ctx context.Context, _ *emptypb.Empty) (*hermesv1.DomainList, error) {
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

func (s *provisionServiceServer) UpdateDomain(ctx context.Context, req *hermesv1.UpdateDomainRequest) (*hermesv1.Domain, error) {
	updateReq := &dto.DomainUpdateRequest{
		Name:        optionalFromPtr(req.Name),
		Description: optionalFromPtr(req.Description),
	}
	d, err := s.svc.UpdateDomain(ctx, req.GetDomainId(), updateReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return domainToProto(d), nil
}

// ==================== Domain IDP Config ====================

func (s *provisionServiceServer) GetDomainIDPConfigs(ctx context.Context, req *hermesv1.GetDomainRequest) (*hermesv1.DomainIDPConfigList, error) {
	configs, err := s.svc.GetDomainIDPConfigs(ctx, req.GetDomainId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.DomainIDPConfig, 0, len(configs))
	for _, cfg := range configs {
		out = append(out, domainIDPConfigToProto(cfg))
	}
	return &hermesv1.DomainIDPConfigList{Configs: out}, nil
}

func (s *provisionServiceServer) CreateDomainIDPConfig(ctx context.Context, req *hermesv1.CreateDomainIDPConfigRequest) (*hermesv1.DomainIDPConfig, error) {
	createReq := &dto.DomainIDPConfigCreateRequest{
		IDPType:  req.GetType(),
		Priority: int(req.GetPriority()),
		Strategy: req.Strategy,
	}
	cfg, err := s.svc.CreateDomainIDPConfig(ctx, req.GetDomainId(), createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return domainIDPConfigToProto(cfg), nil
}

func (s *provisionServiceServer) UpdateDomainIDPConfig(ctx context.Context, req *hermesv1.UpdateDomainIDPConfigRequest) (*hermesv1.DomainIDPConfig, error) {
	updateReq := &dto.DomainIDPConfigUpdateRequest{
		Strategy: optionalFromPtr(req.Strategy),
	}
	if req.Priority != nil {
		updateReq.Priority = optionalIntFromPtr32(req.Priority)
	}

	if err := s.svc.UpdateDomainIDPConfig(ctx, req.GetDomainId(), req.GetType(), updateReq); err != nil {
		return nil, toStatus(err)
	}

	configs, err := s.svc.GetDomainIDPConfigs(ctx, req.GetDomainId())
	if err != nil {
		return nil, toStatus(err)
	}
	for _, cfg := range configs {
		if cfg.IDPType == req.GetType() {
			return domainIDPConfigToProto(cfg), nil
		}
	}
	return nil, toStatus(err)
}

func (s *provisionServiceServer) DeleteDomainIDPConfig(ctx context.Context, req *hermesv1.DeleteDomainIDPConfigRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteDomainIDPConfig(ctx, req.GetDomainId(), req.GetType()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ==================== Application ====================

func (s *provisionServiceServer) CreateApplication(ctx context.Context, req *hermesv1.CreateApplicationRequest) (*hermesv1.Application, error) {
	createReq := &dto.ApplicationCreateRequest{
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

func (s *provisionServiceServer) GetApplication(ctx context.Context, req *hermesv1.GetApplicationRequest) (*hermesv1.Application, error) {
	app, err := s.svc.GetApplication(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return applicationToProto(app), nil
}

func (s *provisionServiceServer) ListApplications(ctx context.Context, req *hermesv1.ListApplicationsRequest) (*hermesv1.ApplicationList, error) {
	listReq := &dto.ListRequest{
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

func (s *provisionServiceServer) UpdateApplication(ctx context.Context, req *hermesv1.UpdateApplicationRequest) (*hermesv1.Application, error) {
	updateReq := &dto.ApplicationUpdateRequest{
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

// ==================== Application IDP Config ====================

func (s *provisionServiceServer) GetApplicationIDPConfigs(ctx context.Context, req *hermesv1.GetApplicationRequest) (*hermesv1.ApplicationIDPConfigList, error) {
	configs, err := s.svc.GetApplicationIDPConfigs(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.ApplicationIDPConfig, 0, len(configs))
	for _, cfg := range configs {
		out = append(out, appIDPConfigToProto(cfg))
	}
	return &hermesv1.ApplicationIDPConfigList{Configs: out}, nil
}

func (s *provisionServiceServer) CreateApplicationIDPConfig(ctx context.Context, req *hermesv1.CreateApplicationIDPConfigRequest) (*hermesv1.ApplicationIDPConfig, error) {
	createReq := &dto.ApplicationIDPConfigCreateRequest{
		Type:     req.GetType(),
		Priority: int(req.GetPriority()),
		Strategy: req.Strategy,
	}
	cfg, err := s.svc.CreateApplicationIDPConfig(ctx, req.GetAppId(), createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return appIDPConfigToProto(cfg), nil
}

func (s *provisionServiceServer) UpdateApplicationIDPConfig(ctx context.Context, req *hermesv1.UpdateApplicationIDPConfigRequest) (*hermesv1.ApplicationIDPConfig, error) {
	updateReq := &dto.ApplicationIDPConfigUpdateRequest{
		Strategy: optionalFromPtr(req.Strategy),
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
			return appIDPConfigToProto(cfg), nil
		}
	}
	return nil, toStatus(err)
}

func (s *provisionServiceServer) DeleteApplicationIDPConfig(ctx context.Context, req *hermesv1.DeleteApplicationIDPConfigRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteApplicationIDPConfig(ctx, req.GetAppId(), req.GetType()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ==================== Service ====================

func (s *provisionServiceServer) CreateService(ctx context.Context, req *hermesv1.CreateServiceRequest) (*hermesv1.Service, error) {
	createReq := &dto.ServiceCreateRequest{
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

func (s *provisionServiceServer) GetService(ctx context.Context, req *hermesv1.GetServiceRequest) (*hermesv1.Service, error) {
	svc, err := s.svc.GetService(ctx, req.GetServiceId())
	if err != nil {
		return nil, toStatus(err)
	}
	return serviceToProto(svc), nil
}

func (s *provisionServiceServer) ListServices(ctx context.Context, req *hermesv1.ListServicesRequest) (*hermesv1.ServiceList, error) {
	listReq := &dto.ListRequest{Filter: req.GetFilter()}
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

func (s *provisionServiceServer) UpdateService(ctx context.Context, req *hermesv1.UpdateServiceRequest) (*hermesv1.Service, error) {
	updateReq := &dto.ServiceUpdateRequest{
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

func (s *provisionServiceServer) DeleteService(ctx context.Context, req *hermesv1.DeleteServiceRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteService(ctx, req.GetServiceId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *provisionServiceServer) GetServiceChallengeSetting(ctx context.Context, req *hermesv1.GetServiceChallengeSettingRequest) (*hermesv1.ServiceChallengeSetting, error) {
	cfg, err := s.svc.GetServiceChallengeSetting(ctx, req.GetServiceId(), req.GetType())
	if err != nil {
		return nil, toStatus(err)
	}
	return challengeSettingToProto(cfg), nil
}

// ==================== conversion helpers ====================

func domainToProto(d *models.Domain) *hermesv1.Domain {
	return &hermesv1.Domain{
		DomainId:    d.DomainID,
		Name:        d.Name,
		Description: d.Description,
	}
}

func applicationToProto(a *models.Application) *hermesv1.Application {
	return &hermesv1.Application{
		Id:                            safeUint32(a.ID),
		DomainId:                      a.DomainID,
		AppId:                         a.AppID,
		Name:                          a.Name,
		Description:                   a.Description,
		LogoUrl:                       a.LogoURL,
		AllowedRedirectUris:           a.GetAllowedRedirectURIs(),
		AllowedOrigins:                a.GetAllowedOrigins(),
		AllowedLogoutUris:             a.GetAllowedLogoutURIs(),
		IdTokenExpiresIn:              safeUint32(a.IDTokenExpiresIn),
		RefreshTokenExpiresIn:         safeUint32(a.RefreshTokenExpiresIn),
		RefreshTokenAbsoluteExpiresIn: safeUint32(a.RefreshTokenAbsoluteExpiresIn),
		CreatedAt:                     timestamppb.New(a.CreatedAt),
		UpdatedAt:                     timestamppb.New(a.UpdatedAt),
	}
}

func appIDPConfigToProto(cfg *models.ApplicationIDPConfig) *hermesv1.ApplicationIDPConfig {
	return &hermesv1.ApplicationIDPConfig{
		Id:        safeUint32(cfg.ID),
		AppId:     cfg.AppID,
		Type:      cfg.Type,
		Priority:  safeInt32(cfg.Priority),
		Strategy:  cfg.Strategy,
		CreatedAt: timestamppb.New(cfg.CreatedAt),
		UpdatedAt: timestamppb.New(cfg.UpdatedAt),
	}
}

func domainIDPConfigToProto(cfg *models.DomainIDPConfig) *hermesv1.DomainIDPConfig {
	return &hermesv1.DomainIDPConfig{
		Id:        safeUint32(cfg.ID),
		DomainId:  cfg.DomainID,
		Type:      cfg.IDPType,
		Priority:  safeInt32(cfg.Priority),
		Strategy:  cfg.Strategy,
		CreatedAt: timestamppb.New(cfg.CreatedAt),
		UpdatedAt: timestamppb.New(cfg.UpdatedAt),
	}
}

func serviceToProto(svc *models.Service) *hermesv1.Service {
	pb := &hermesv1.Service{
		Id:                    safeUint32(svc.ID),
		DomainId:              svc.DomainID,
		ServiceId:             svc.ServiceID,
		Name:                  svc.Name,
		Description:           svc.Description,
		LogoUrl:               svc.LogoURL,
		AccessTokenExpiresIn:  safeUint32(svc.AccessTokenExpiresIn),
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
		limits[k] = safeInt32(v)
	}
	return &hermesv1.ServiceChallengeSetting{
		Id:        safeUint32(cfg.ID),
		ServiceId: cfg.ServiceID,
		Type:      cfg.Type,
		ExpiresIn: safeUint32(cfg.ExpiresIn),
		Limits:    limits,
		CreatedAt: timestamppb.New(cfg.CreatedAt),
		UpdatedAt: timestamppb.New(cfg.UpdatedAt),
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
