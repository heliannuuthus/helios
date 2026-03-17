package hermesclient

import (
	"context"
	"fmt"
	"time"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/pkg/dto"
	"github.com/heliannuuthus/helios/pkg/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
)

// ==================== Service ====================

func (c *Client) CreateService(ctx context.Context, req *dto.ServiceCreateRequest) (*models.Service, error) {
	pbReq := &hermesv1.CreateServiceRequest{
		ServiceId:   req.ServiceID,
		DomainId:    req.DomainID,
		Name:        req.Name,
		Description: req.Description,
		LogoUrl:     req.LogoURL,
	}
	if req.AccessTokenExpiresIn != nil {
		v := safeUint32(*req.AccessTokenExpiresIn)
		pbReq.AccessTokenExpiresIn = &v
	}
	resp, err := c.resource.CreateService(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建服务失败: %w", err)
	}
	return serviceFromProto(resp), nil
}

func (c *Client) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	resp, err := c.resource.GetService(ctx, &hermesv1.GetServiceRequest{ServiceId: serviceID})
	if err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	return serviceFromProto(resp), nil
}

func (c *Client) GetServiceWithKey(ctx context.Context, serviceID string) (*models.ServiceWithKey, error) {
	svc, err := c.resource.GetService(ctx, &hermesv1.GetServiceRequest{ServiceId: serviceID})
	if err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	keySet, err := c.key.GetKeys(ctx, &hermesv1.GetKeysRequest{OwnerType: "service", OwnerId: serviceID})
	if err != nil {
		return nil, fmt.Errorf("获取服务密钥失败: %w", err)
	}
	return serviceWithKeyFromProto(svc, keySet), nil
}

func (c *Client) ListServices(ctx context.Context, domainID string, req *dto.ListRequest) (*pagination.Items[models.Service], error) {
	pbReq := &hermesv1.ListServicesRequest{
		DomainId: domainID,
		Filter:   req.Filter,
		Pagination: &hermesv1.Pagination{
			Cursor: req.Token,
			Limit:  safeInt32(req.Size),
		},
	}
	resp, err := c.resource.ListServices(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("列出服务失败: %w", err)
	}
	items := make([]models.Service, 0, len(resp.Services))
	for _, s := range resp.Services {
		items = append(items, *serviceFromProto(s))
	}
	return &pagination.Items[models.Service]{
		Items: items,
		Next:  resp.NextCursor,
	}, nil
}

func (c *Client) UpdateService(ctx context.Context, serviceID string, req *dto.ServiceUpdateRequest) error {
	pbReq := &hermesv1.UpdateServiceRequest{ServiceId: serviceID}
	if req.Name.IsPresent() && !req.Name.IsNull() {
		v := req.Name.Value()
		pbReq.Name = &v
	}
	if req.Description.IsPresent() && !req.Description.IsNull() {
		v := req.Description.Value()
		pbReq.Description = &v
	}
	if req.LogoURL.IsPresent() && !req.LogoURL.IsNull() {
		v := req.LogoURL.Value()
		pbReq.LogoUrl = &v
	}
	if req.AccessTokenExpiresIn.IsPresent() && !req.AccessTokenExpiresIn.IsNull() {
		v := safeUint32(req.AccessTokenExpiresIn.Value())
		pbReq.AccessTokenExpiresIn = &v
	}
	_, err := c.resource.UpdateService(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新服务失败: %w", err)
	}
	return nil
}

func (c *Client) DeleteService(ctx context.Context, serviceID string) error {
	_, err := c.resource.DeleteService(ctx, &hermesv1.DeleteServiceRequest{ServiceId: serviceID})
	if err != nil {
		return fmt.Errorf("删除服务失败: %w", err)
	}
	return nil
}

func (c *Client) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error) {
	resp, err := c.resource.GetServiceChallengeSetting(ctx, &hermesv1.GetServiceChallengeSettingRequest{
		ServiceId: serviceID,
		Type:      challengeType,
	})
	if err != nil {
		return nil, fmt.Errorf("获取 Challenge 配置失败: %w", err)
	}
	return challengeSettingFromProto(resp), nil
}

func (c *Client) GetServiceApplicationRelations(ctx context.Context, serviceID string) ([]models.ApplicationServiceRelation, error) {
	resp, err := c.resource.GetServiceApplicationRelations(ctx, &hermesv1.GetServiceRequest{ServiceId: serviceID})
	if err != nil {
		return nil, fmt.Errorf("获取服务已授权应用失败: %w", err)
	}
	relations := make([]models.ApplicationServiceRelation, 0, len(resp.Relations))
	for _, r := range resp.Relations {
		relations = append(relations, appServiceRelationFromProto(r))
	}
	return relations, nil
}

// ==================== Relationship ====================

func (c *Client) CreateRelationship(ctx context.Context, req *dto.RelationshipCreateRequest) (*models.Relationship, error) {
	pbReq := &hermesv1.CreateRelationshipRequest{
		ServiceId:   req.ServiceID,
		SubjectType: req.SubjectType,
		SubjectId:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectId:    req.ObjectID,
	}
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		pbReq.ExpiresAt = toTimestamp(exp)
	}
	resp, err := c.resource.CreateRelationship(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建关系失败: %w", err)
	}
	return relationshipFromProto(resp), nil
}

func (c *Client) DeleteRelationship(ctx context.Context, req *dto.RelationshipDeleteRequest) error {
	_, err := c.resource.DeleteRelationship(ctx, &hermesv1.DeleteRelationshipRequest{
		ServiceId:   req.ServiceID,
		SubjectType: req.SubjectType,
		SubjectId:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectId:    req.ObjectID,
	})
	if err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}
	return nil
}

func (c *Client) UpdateRelationship(ctx context.Context, req *dto.RelationshipUpdateRequest) (*models.Relationship, error) {
	pbReq := &hermesv1.UpdateRelationshipRequest{
		ServiceId:   req.ServiceID,
		SubjectType: req.SubjectType,
		SubjectId:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectId:    req.ObjectID,
	}
	if req.NewRelation.IsPresent() && !req.NewRelation.IsNull() {
		v := req.NewRelation.Value()
		pbReq.NewRelation = &v
	}
	if req.ExpiresAt.IsPresent() && !req.ExpiresAt.IsNull() {
		exp, err := time.Parse(time.RFC3339, req.ExpiresAt.Value())
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		pbReq.ExpiresAt = toTimestamp(exp)
	}
	resp, err := c.resource.UpdateRelationship(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("更新关系失败: %w", err)
	}
	return relationshipFromProto(resp), nil
}

func (c *Client) ListRelationships(ctx context.Context, req *dto.ListRequest) (*pagination.Items[models.Relationship], error) {
	pbReq := &hermesv1.ListRelationshipsRequest{
		Filter: req.Filter,
		Pagination: &hermesv1.Pagination{
			Cursor: req.Token,
			Limit:  safeInt32(req.Size),
		},
	}
	resp, err := c.resource.ListRelationships(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("列出关系失败: %w", err)
	}
	items := make([]models.Relationship, 0, len(resp.Relationships))
	for _, r := range resp.Relationships {
		items = append(items, *relationshipFromProto(r))
	}
	return &pagination.Items[models.Relationship]{
		Items: items,
		Next:  resp.NextCursor,
	}, nil
}

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

// ==================== App Service Relationship ====================

func (c *Client) ListAppServiceRelationships(ctx context.Context, appID, serviceID string, req *dto.ListRequest) (*pagination.Items[models.Relationship], error) {
	pbReq := &hermesv1.ListAppServiceRelationshipsRequest{
		AppId:     appID,
		ServiceId: serviceID,
		Filter:    req.Filter,
		Pagination: &hermesv1.Pagination{
			Cursor: req.Token,
			Limit:  safeInt32(req.Size),
		},
	}
	resp, err := c.resource.ListAppServiceRelationships(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("列出应用服务关系失败: %w", err)
	}
	items := make([]models.Relationship, 0, len(resp.Relationships))
	for _, r := range resp.Relationships {
		items = append(items, *relationshipFromProto(r))
	}
	return &pagination.Items[models.Relationship]{
		Items: items,
		Next:  resp.NextCursor,
	}, nil
}

func (c *Client) CreateAppServiceRelationship(ctx context.Context, appID, serviceID string, req *dto.AppServiceRelationshipCreateRequest) (*models.Relationship, error) {
	pbReq := &hermesv1.CreateAppServiceRelationshipRequest{
		AppId:       appID,
		ServiceId:   serviceID,
		SubjectType: req.SubjectType,
		SubjectId:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectId:    req.ObjectID,
	}
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		pbReq.ExpiresAt = toTimestamp(exp)
	}
	resp, err := c.resource.CreateAppServiceRelationship(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建应用服务关系失败: %w", err)
	}
	return relationshipFromProto(resp), nil
}

func (c *Client) UpdateAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint, req *dto.AppServiceRelationshipUpdateRequest) (*models.Relationship, error) {
	pbReq := &hermesv1.UpdateAppServiceRelationshipRequest{
		AppId:          appID,
		ServiceId:      serviceID,
		RelationshipId: safeUint32(relationshipID),
	}
	if req.NewRelation.IsPresent() && !req.NewRelation.IsNull() {
		v := req.NewRelation.Value()
		pbReq.NewRelation = &v
	}
	if req.ExpiresAt.IsPresent() {
		if !req.ExpiresAt.IsNull() {
			exp, err := time.Parse(time.RFC3339, req.ExpiresAt.Value())
			if err != nil {
				return nil, fmt.Errorf("解析过期时间失败: %w", err)
			}
			pbReq.ExpiresAt = toTimestamp(exp)
		}
	}
	resp, err := c.resource.UpdateAppServiceRelationship(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("更新应用服务关系失败: %w", err)
	}
	return relationshipFromProto(resp), nil
}

func (c *Client) DeleteAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint) error {
	_, err := c.resource.DeleteAppServiceRelationship(ctx, &hermesv1.DeleteAppServiceRelationshipRequest{
		AppId:          appID,
		ServiceId:      serviceID,
		RelationshipId: safeUint32(relationshipID),
	})
	if err != nil {
		return fmt.Errorf("删除应用服务关系失败: %w", err)
	}
	return nil
}

// ==================== Group ====================

func (c *Client) CreateGroup(ctx context.Context, req *dto.GroupCreateRequest) (*models.Group, error) {
	pbReq := &hermesv1.CreateGroupRequest{
		GroupId:   req.GroupID,
		ServiceId: req.ServiceID,
		Name:      req.Name,
	}
	if req.Description != nil {
		pbReq.Description = req.Description
	}
	resp, err := c.resource.CreateGroup(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建组失败: %w", err)
	}
	return groupFromProto(resp), nil
}

func (c *Client) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	resp, err := c.resource.GetGroup(ctx, &hermesv1.GetGroupRequest{GroupId: groupID})
	if err != nil {
		return nil, fmt.Errorf("获取组失败: %w", err)
	}
	return groupFromProto(resp), nil
}

func (c *Client) ListGroups(ctx context.Context, req *dto.ListRequest) (*pagination.Items[models.Group], error) {
	pbReq := &hermesv1.ListGroupsRequest{
		Filter: req.Filter,
		Pagination: &hermesv1.Pagination{
			Cursor: req.Token,
			Limit:  safeInt32(req.Size),
		},
	}
	resp, err := c.resource.ListGroups(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("列出组失败: %w", err)
	}
	items := make([]models.Group, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		items = append(items, *groupFromProto(g))
	}
	return &pagination.Items[models.Group]{
		Items: items,
		Next:  resp.NextCursor,
	}, nil
}

func (c *Client) UpdateGroup(ctx context.Context, groupID string, req *dto.GroupUpdateRequest) error {
	pbReq := &hermesv1.UpdateGroupRequest{GroupId: groupID}
	if req.Name.IsPresent() && !req.Name.IsNull() {
		v := req.Name.Value()
		pbReq.Name = &v
	}
	if req.Description.IsPresent() && !req.Description.IsNull() {
		v := req.Description.Value()
		pbReq.Description = &v
	}
	_, err := c.resource.UpdateGroup(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新组失败: %w", err)
	}
	return nil
}

func (c *Client) DeleteGroup(ctx context.Context, groupID string) error {
	_, err := c.resource.DeleteGroup(ctx, &hermesv1.GetGroupRequest{GroupId: groupID})
	if err != nil {
		return fmt.Errorf("删除组失败: %w", err)
	}
	return nil
}

func (c *Client) SetGroupMembers(ctx context.Context, req *dto.GroupMemberRequest) error {
	_, err := c.resource.SetGroupMembers(ctx, &hermesv1.SetGroupMembersRequest{
		GroupId: req.GroupID,
		UserIds: req.UserIDs,
	})
	if err != nil {
		return fmt.Errorf("设置组成员失败: %w", err)
	}
	return nil
}

func (c *Client) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	resp, err := c.resource.GetGroupMembers(ctx, &hermesv1.GetGroupRequest{GroupId: groupID})
	if err != nil {
		return nil, fmt.Errorf("获取组成员失败: %w", err)
	}
	return resp.Values, nil
}
