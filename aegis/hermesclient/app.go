package hermesclient

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/emptypb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/pkg/dto"
	"github.com/heliannuuthus/helios/pkg/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Domain ====================

func (c *Client) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	resp, err := c.provision.GetDomain(ctx, &hermesv1.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, fmt.Errorf("获取域失败: %w", err)
	}
	return domainFromProto(resp), nil
}

func (c *Client) GetDomainIDPConfigs(ctx context.Context, domainID string) ([]*models.DomainIDPConfig, error) {
	resp, err := c.provision.GetDomainIDPConfigs(ctx, &hermesv1.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, fmt.Errorf("获取域 IDP 配置失败: %w", err)
	}
	configs := make([]*models.DomainIDPConfig, 0, len(resp.Configs))
	for _, cfg := range resp.Configs {
		configs = append(configs, domainIDPConfigFromProto(cfg))
	}
	return configs, nil
}

func (c *Client) ListDomains(ctx context.Context) ([]models.Domain, error) {
	resp, err := c.provision.ListDomains(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("列出域失败: %w", err)
	}
	domains := make([]models.Domain, 0, len(resp.Domains))
	for _, d := range resp.Domains {
		domains = append(domains, *domainFromProto(d))
	}
	return domains, nil
}

func (c *Client) UpdateDomain(ctx context.Context, domainID string, req *dto.DomainUpdateRequest) (*models.Domain, error) {
	pbReq := &hermesv1.UpdateDomainRequest{DomainId: domainID}
	if req.Name.IsPresent() && !req.Name.IsNull() {
		v := req.Name.Value()
		pbReq.Name = &v
	}
	if req.Description.IsPresent() && !req.Description.IsNull() {
		v := req.Description.Value()
		pbReq.Description = &v
	}
	resp, err := c.provision.UpdateDomain(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("更新域失败: %w", err)
	}
	return domainFromProto(resp), nil
}

// ==================== Application ====================

func (c *Client) CreateApplication(ctx context.Context, req *dto.ApplicationCreateRequest) (*models.Application, error) {
	pbReq := &hermesv1.CreateApplicationRequest{
		DomainId:            req.DomainID,
		Name:                req.Name,
		Description:         req.Description,
		AllowedRedirectUris: req.AllowedRedirectURIs,
		AllowedOrigins:      req.AllowedOrigins,
		AllowedLogoutUris:   req.AllowedLogoutURIs,
		NeedKey:             req.NeedKey,
	}
	if req.AppID != "" {
		pbReq.AppId = &req.AppID
	}
	if req.IDTokenExpiresIn != nil {
		v := safeUint32(*req.IDTokenExpiresIn)
		pbReq.IdTokenExpiresIn = &v
	}
	if req.RefreshTokenExpiresIn != nil {
		v := safeUint32(*req.RefreshTokenExpiresIn)
		pbReq.RefreshTokenExpiresIn = &v
	}
	if req.RefreshTokenAbsoluteExpiresIn != nil {
		v := safeUint32(*req.RefreshTokenAbsoluteExpiresIn)
		pbReq.RefreshTokenAbsoluteExpiresIn = &v
	}
	resp, err := c.provision.CreateApplication(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建应用失败: %w", err)
	}
	return applicationFromProto(resp), nil
}

func (c *Client) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	resp, err := c.provision.GetApplication(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	return applicationFromProto(resp), nil
}

func (c *Client) ListApplications(ctx context.Context, domainID string, req *dto.ListRequest) (*pagination.Items[models.Application], error) {
	pbReq := &hermesv1.ListApplicationsRequest{
		DomainId: domainID,
		Filter:   req.Filter,
		Pagination: &hermesv1.Pagination{
			Cursor: req.Token,
			Limit:  safeInt32(req.Size),
		},
	}
	resp, err := c.provision.ListApplications(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("列出应用失败: %w", err)
	}
	items := make([]models.Application, 0, len(resp.Applications))
	for _, a := range resp.Applications {
		items = append(items, *applicationFromProto(a))
	}
	return &pagination.Items[models.Application]{
		Items: items,
		Next:  resp.NextCursor,
	}, nil
}

func (c *Client) UpdateApplication(ctx context.Context, appID string, req *dto.ApplicationUpdateRequest) error {
	pbReq := &hermesv1.UpdateApplicationRequest{AppId: appID}
	setOptionalString(&pbReq.Name, req.Name)
	setOptionalString(&pbReq.Description, req.Description)
	setOptionalString(&pbReq.LogoUrl, req.LogoURL)
	setOptionalUint32(&pbReq.IdTokenExpiresIn, req.IDTokenExpiresIn)
	setOptionalUint32(&pbReq.RefreshTokenExpiresIn, req.RefreshTokenExpiresIn)
	setOptionalUint32(&pbReq.RefreshTokenAbsoluteExpiresIn, req.RefreshTokenAbsoluteExpiresIn)
	if req.AllowedRedirectURIs.IsPresent() {
		pbReq.AllowedRedirectUris = optionalStringListToProto(req.AllowedRedirectURIs)
	}
	if req.AllowedOrigins.IsPresent() {
		pbReq.AllowedOrigins = optionalStringListToProto(req.AllowedOrigins)
	}
	if req.AllowedLogoutURIs.IsPresent() {
		pbReq.AllowedLogoutUris = optionalStringListToProto(req.AllowedLogoutURIs)
	}
	_, err := c.provision.UpdateApplication(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新应用失败: %w", err)
	}
	return nil
}

// ==================== Application IDP Config ====================

func (c *Client) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error) {
	resp, err := c.provision.GetApplicationIDPConfigs(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用 IDP 配置失败: %w", err)
	}
	configs := make([]*models.ApplicationIDPConfig, 0, len(resp.Configs))
	for _, cfg := range resp.Configs {
		configs = append(configs, idpConfigFromProto(cfg))
	}
	return configs, nil
}

func (c *Client) CreateApplicationIDPConfig(ctx context.Context, appID string, req *dto.ApplicationIDPConfigCreateRequest) (*models.ApplicationIDPConfig, error) {
	pbReq := &hermesv1.CreateApplicationIDPConfigRequest{
		AppId:    appID,
		Type:     req.Type,
		Priority: safeInt32(req.Priority),
		Strategy: req.Strategy,
	}
	resp, err := c.provision.CreateApplicationIDPConfig(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建应用 IDP 配置失败: %w", err)
	}
	return idpConfigFromProto(resp), nil
}

func (c *Client) UpdateApplicationIDPConfig(ctx context.Context, appID, idpType string, req *dto.ApplicationIDPConfigUpdateRequest) error {
	pbReq := &hermesv1.UpdateApplicationIDPConfigRequest{
		AppId: appID,
		Type:  idpType,
	}
	if req.Priority.IsPresent() && !req.Priority.IsNull() {
		v := safeInt32(req.Priority.Value())
		pbReq.Priority = &v
	}
	if req.Strategy.IsPresent() && !req.Strategy.IsNull() {
		v := req.Strategy.Value()
		pbReq.Strategy = &v
	}
	_, err := c.provision.UpdateApplicationIDPConfig(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新应用 IDP 配置失败: %w", err)
	}
	return nil
}

func (c *Client) DeleteApplicationIDPConfig(ctx context.Context, appID, idpType string) error {
	_, err := c.provision.DeleteApplicationIDPConfig(ctx, &hermesv1.DeleteApplicationIDPConfigRequest{
		AppId: appID,
		Type:  idpType,
	})
	if err != nil {
		return fmt.Errorf("删除应用 IDP 配置失败: %w", err)
	}
	return nil
}

// ==================== helpers ====================

func optionalStringListToProto(opt patch.Optional[[]string]) *hermesv1.OptionalStringList {
	if !opt.IsPresent() {
		return nil
	}
	if opt.IsNull() {
		return &hermesv1.OptionalStringList{Values: nil}
	}
	return &hermesv1.OptionalStringList{Values: opt.Value()}
}
