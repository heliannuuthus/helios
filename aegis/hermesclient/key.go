package hermesclient

import (
	"context"
	"fmt"
	"time"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes/models"
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

func (c *Client) RotateKey(ctx context.Context, ownerType, ownerID string, window time.Duration) error {
	_, err := c.key.RotateKey(ctx, &hermesv1.RotateKeyRequest{
		OwnerType:     ownerType,
		OwnerId:       ownerID,
		WindowSeconds: int64(window.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("轮换密钥失败: %w", err)
	}
	return nil
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
