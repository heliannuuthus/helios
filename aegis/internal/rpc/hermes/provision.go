package hermes

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/aegis/internal/models"
	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
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
	configs := make([]*models.DomainIDPConfig, 0, len(resp.GetConfigs()))
	for _, cfg := range resp.GetConfigs() {
		configs = append(configs, domainIDPConfigFromProto(cfg))
	}
	return configs, nil
}

// ==================== Application ====================

func (c *Client) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	resp, err := c.provision.GetApplication(ctx, &hermesv1.GetApplicationRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	return applicationFromProto(resp), nil
}

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

// ==================== Service ====================

func (c *Client) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	resp, err := c.provision.GetService(ctx, &hermesv1.GetServiceRequest{ServiceId: serviceID})
	if err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	return serviceFromProto(resp), nil
}

func (c *Client) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error) {
	resp, err := c.provision.GetServiceChallengeSetting(ctx, &hermesv1.GetServiceChallengeSettingRequest{
		ServiceId: serviceID,
		Type:      challengeType,
	})
	if err != nil {
		return nil, fmt.Errorf("获取 Challenge 配置失败: %w", err)
	}
	return challengeSettingFromProto(resp), nil
}
