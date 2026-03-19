package grpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
)

type provisionServiceServer struct {
	hermesv1.UnimplementedProvisionServiceServer
	svc *hermes.ProvisionService
}

func NewProvisionServiceServer(svc *hermes.ProvisionService) hermesv1.ProvisionServiceServer {
	return &provisionServiceServer{svc: svc}
}

func (s *provisionServiceServer) GetDomain(ctx context.Context, req *hermesv1.GetDomainRequest) (*hermesv1.Domain, error) {
	d, err := s.svc.GetDomain(ctx, req.GetDomainId())
	if err != nil {
		return nil, toStatus(err)
	}
	return domainToProto(d), nil
}

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

func (s *provisionServiceServer) GetApplication(ctx context.Context, req *hermesv1.GetApplicationRequest) (*hermesv1.Application, error) {
	app, err := s.svc.GetApplication(ctx, req.GetAppId())
	if err != nil {
		return nil, toStatus(err)
	}
	return applicationToProto(app), nil
}

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

func (s *provisionServiceServer) GetService(ctx context.Context, req *hermesv1.GetServiceRequest) (*hermesv1.Service, error) {
	svc, err := s.svc.GetService(ctx, req.GetServiceId())
	if err != nil {
		return nil, toStatus(err)
	}
	return serviceToProto(svc), nil
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
