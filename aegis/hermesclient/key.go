package hermesclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/pkg/dto"
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

// ==================== IDP Key ====================

func (c *Client) GetIDPKeys(ctx context.Context) ([]*models.IDPKey, error) {
	resp, err := c.key.ListIDPKeys(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("获取 IDP 密钥列表失败: %w", err)
	}
	keys := make([]*models.IDPKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, idpKeyFromProto(k))
	}
	return keys, nil
}

func (c *Client) GetIDPKey(ctx context.Context, idpType, tAppID string) (*models.IDPKey, error) {
	resp, err := c.key.GetIDPKey(ctx, &hermesv1.GetIDPKeyRequest{IdpType: idpType, TAppId: tAppID})
	if err != nil {
		return nil, fmt.Errorf("获取 IDP 密钥失败: %w", err)
	}
	return idpKeyFromProto(resp), nil
}

func (c *Client) CreateIDPKey(ctx context.Context, req *dto.IDPKeyCreateRequest) (*models.IDPKey, error) {
	resp, err := c.key.CreateIDPKey(ctx, &hermesv1.CreateIDPKeyRequest{
		IdpType: req.IDPType,
		TAppId:  req.TAppID,
		TSecret: req.TSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("创建 IDP 密钥失败: %w", err)
	}
	return idpKeyFromProto(resp), nil
}

func (c *Client) UpdateIDPKey(ctx context.Context, idpType, tAppID string, req *dto.IDPKeyUpdateRequest) error {
	pbReq := &hermesv1.UpdateIDPKeyRequest{
		IdpType: idpType,
		TAppId:  tAppID,
	}
	if req.TSecret.IsPresent() && !req.TSecret.IsNull() {
		v := req.TSecret.Value()
		pbReq.TSecret = &v
	}
	_, err := c.key.UpdateIDPKey(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新 IDP 密钥失败: %w", err)
	}
	return nil
}

func (c *Client) DeleteIDPKey(ctx context.Context, idpType, tAppID string) error {
	_, err := c.key.DeleteIDPKey(ctx, &hermesv1.DeleteIDPKeyRequest{
		IdpType: idpType,
		TAppId:  tAppID,
	})
	if err != nil {
		return fmt.Errorf("删除 IDP 密钥失败: %w", err)
	}
	return nil
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
