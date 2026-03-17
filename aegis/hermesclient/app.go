package hermesclient

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/emptypb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Domain ====================

func (c *Client) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	resp, err := c.app.GetDomain(ctx, &hermesv1.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, fmt.Errorf("获取域失败: %w", err)
	}
	return domainFromProto(resp), nil
}

func (c *Client) GetDomainAllowedIDPs(ctx context.Context, domainID string) ([]string, error) {
	resp, err := c.app.GetDomainAllowedIDPs(ctx, &hermesv1.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, fmt.Errorf("获取域允许的 IDP 列表失败: %w", err)
	}
	return resp.Values, nil
}

func (c *Client) GetDomainWithKey(ctx context.Context, domainID string) (*models.DomainWithKey, error) {
	domain, err := c.app.GetDomain(ctx, &hermesv1.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, fmt.Errorf("获取域失败: %w", err)
	}
	keySet, err := c.key.GetKeys(ctx, &hermesv1.GetKeysRequest{OwnerType: "domain", OwnerId: domainID})
	if err != nil {
		return nil, fmt.Errorf("获取域密钥失败: %w", err)
	}
	return domainWithKeyFromProto(domain, keySet), nil
}

func (c *Client) ListDomains(ctx context.Context) ([]models.Domain, error) {
	resp, err := c.app.ListDomains(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("列出域失败: %w", err)
	}
	domains := make([]models.Domain, 0, len(resp.Domains))
	for _, d := range resp.Domains {
		domains = append(domains, *domainFromProto(d))
	}
	return domains, nil
}

func (c *Client) UpdateDomain(ctx context.Context, domainID string, req *hermes.DomainUpdateRequest) (*models.Domain, error) {
	pbReq := &hermesv1.UpdateDomainRequest{DomainId: domainID}
	if req.Name.IsPresent() && !req.Name.IsNull() {
		v := req.Name.Value()
		pbReq.Name = &v
	}
	if req.Description.IsPresent() && !req.Description.IsNull() {
		v := req.Description.Value()
		pbReq.Description = &v
	}
	resp, err := c.app.UpdateDomain(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("更新域失败: %w", err)
	}
	return domainFromProto(resp), nil
}

// ==================== Application ====================

func (c *Client) CreateApplication(ctx context.Context, req *hermes.ApplicationCreateRequest) (*models.Application, error) {
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
	resp, err := c.app.CreateApplication(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建应用失败: %w", err)
	}
	return applicationFromProto(resp), nil
}

func (c *Client) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	resp, err := c.app.GetApplication(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	return applicationFromProto(resp), nil
}

func (c *Client) GetApplicationWithKey(ctx context.Context, appID string) (*models.ApplicationWithKey, error) {
	app, err := c.app.GetApplication(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	keySet, err := c.key.GetKeys(ctx, &hermesv1.GetKeysRequest{OwnerType: "application", OwnerId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用密钥失败: %w", err)
	}
	return applicationWithKeyFromProto(app, keySet), nil
}

func (c *Client) ListApplications(ctx context.Context, domainID string, req *hermes.ListRequest) (*pagination.Items[models.Application], error) {
	pbReq := &hermesv1.ListApplicationsRequest{
		DomainId: domainID,
		Filter:   req.Filter,
		Pagination: &hermesv1.Pagination{
			Cursor: req.Token,
			Limit:  safeInt32(req.Size),
		},
	}
	resp, err := c.app.ListApplications(ctx, pbReq)
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

func (c *Client) UpdateApplication(ctx context.Context, appID string, req *hermes.ApplicationUpdateRequest) error {
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
	_, err := c.app.UpdateApplication(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新应用失败: %w", err)
	}
	return nil
}

// ==================== Application IDP Config ====================

func (c *Client) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error) {
	resp, err := c.app.GetApplicationIDPConfigs(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用 IDP 配置失败: %w", err)
	}
	configs := make([]*models.ApplicationIDPConfig, 0, len(resp.Configs))
	for _, cfg := range resp.Configs {
		configs = append(configs, idpConfigFromProto(cfg))
	}
	return configs, nil
}

func (c *Client) CreateApplicationIDPConfig(ctx context.Context, appID string, req *hermes.ApplicationIDPConfigCreateRequest) (*models.ApplicationIDPConfig, error) {
	pbReq := &hermesv1.CreateApplicationIDPConfigRequest{
		AppId:    appID,
		Type:     req.Type,
		Priority: safeInt32(req.Priority),
		Strategy: req.Strategy,
		Delegate: req.Delegate,
		Require:  req.Require,
	}
	resp, err := c.app.CreateApplicationIDPConfig(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建应用 IDP 配置失败: %w", err)
	}
	return idpConfigFromProto(resp), nil
}

func (c *Client) UpdateApplicationIDPConfig(ctx context.Context, appID, idpType string, req *hermes.ApplicationIDPConfigUpdateRequest) error {
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
	if req.Delegate.IsPresent() && !req.Delegate.IsNull() {
		v := req.Delegate.Value()
		pbReq.Delegate = &v
	}
	if req.Require.IsPresent() && !req.Require.IsNull() {
		v := req.Require.Value()
		pbReq.Require = &v
	}
	_, err := c.app.UpdateApplicationIDPConfig(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新应用 IDP 配置失败: %w", err)
	}
	return nil
}

func (c *Client) DeleteApplicationIDPConfig(ctx context.Context, appID, idpType string) error {
	_, err := c.app.DeleteApplicationIDPConfig(ctx, &hermesv1.DeleteApplicationIDPConfigRequest{
		AppId: appID,
		Type:  idpType,
	})
	if err != nil {
		return fmt.Errorf("删除应用 IDP 配置失败: %w", err)
	}
	return nil
}

// ==================== Application Service Relations ====================

func (c *Client) SetApplicationServiceRelations(ctx context.Context, req *hermes.ApplicationServiceRelationRequest) error {
	_, err := c.app.SetApplicationServiceRelations(ctx, &hermesv1.SetApplicationServiceRelationsRequest{
		AppId:     req.AppID,
		ServiceId: req.ServiceID,
		Relations: req.Relations,
	})
	if err != nil {
		return fmt.Errorf("设置应用服务关系失败: %w", err)
	}
	return nil
}

func (c *Client) GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	resp, err := c.app.GetApplicationServiceRelations(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用服务关系失败: %w", err)
	}
	relations := make([]models.ApplicationServiceRelation, 0, len(resp.Relations))
	for _, r := range resp.Relations {
		relations = append(relations, appServiceRelationFromProto(r))
	}
	return relations, nil
}

func (c *Client) GetServiceAppRelations(ctx context.Context, serviceID, appID string) ([]string, error) {
	resp, err := c.app.GetServiceAppRelations(ctx, &hermesv1.GetServiceAppRelationsRequest{
		ServiceId: serviceID,
		AppId:     appID,
	})
	if err != nil {
		return nil, fmt.Errorf("获取服务应用关系失败: %w", err)
	}
	return resp.Values, nil
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
