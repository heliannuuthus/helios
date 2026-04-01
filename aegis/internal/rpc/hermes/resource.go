package hermes

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/aegis/internal/models"
	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
)

// ==================== Application Service Relations ====================

func (c *Client) GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	resp, err := c.resource.GetApplicationServiceRelations(ctx, &hermesv1.GetApplicationServiceRelationsRequest{AppId: appID})
	if err != nil {
		return nil, fmt.Errorf("获取应用服务关系失败: %w", err)
	}
	relations := make([]models.ApplicationServiceRelation, 0, len(resp.Relations))
	for _, r := range resp.Relations {
		relations = append(relations, appServiceRelationFromProto(r))
	}
	return relations, nil
}

// ==================== Relationship ====================

func (c *Client) FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	resp, err := c.resource.FindRelationships(ctx, &hermesv1.FindRelationshipsRequest{
		ServiceId:   serviceID,
		SubjectType: subjectType,
		SubjectId:   subjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("查询关系失败: %w", err)
	}
	items := make([]models.Relationship, 0, len(resp.Items))
	for _, r := range resp.Items {
		items = append(items, *relationshipFromProto(r))
	}
	return items, nil
}
