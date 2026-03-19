package hermes

import (
	"context"
	"fmt"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/pkg/models"
)

func (c *Client) GetDomainKeys(ctx context.Context, domainID string) ([][]byte, error) {
	return c.getKeysByOwner(ctx, models.KeyOwnerDomain, domainID)
}

func (c *Client) GetApplicationKeys(ctx context.Context, appID string) ([][]byte, error) {
	return c.getKeysByOwner(ctx, models.KeyOwnerApplication, appID)
}

func (c *Client) GetServiceKeys(ctx context.Context, serviceID string) ([][]byte, error) {
	return c.getKeysByOwner(ctx, models.KeyOwnerService, serviceID)
}

func (c *Client) getKeysByOwner(ctx context.Context, ownerType, ownerID string) ([][]byte, error) {
	resp, err := c.key.GetKeys(ctx, &hermesv1.GetKeysRequest{
		OwnerType: ownerType,
		OwnerId:   ownerID,
	})
	if err != nil {
		return nil, fmt.Errorf("获取密钥失败: %w", err)
	}
	return resp.Keys, nil
}

func (c *Client) ResolveIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error) {
	resp, err := c.key.ResolveIDPKey(ctx, &hermesv1.ResolveIDPKeyRequest{
		AppId:   appID,
		IdpType: idpType,
	})
	if err != nil {
		return "", "", fmt.Errorf("解析 IDP 密钥失败: %w", err)
	}
	return resp.TAppId, resp.TSecret, nil
}
