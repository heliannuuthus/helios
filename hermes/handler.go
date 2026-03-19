package hermes

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
)

// Handler hermes HTTP 处理器
type Handler struct {
	provision *ProvisionService
	resource  *ResourceService
	key       *KeyService
	user      *UserService
}

// NewHandler 创建 hermes HTTP 处理器
func NewHandler(ps *ProvisionService, rs *ResourceService, ks *KeyService, us *UserService) *Handler {
	return &Handler{provision: ps, resource: rs, key: ks, user: us}
}

// ==================== Domain 相关 ====================

func (h *Handler) GetDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	domain, err := h.provision.GetDomain(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.DomainResponse{
		DomainID:    domain.DomainID,
		Name:        domain.Name,
		Description: domain.Description,
	})
}

// ==================== IDP Key 相关 ====================

func (h *Handler) ListIDPKeys(c *gin.Context) {
	secrets, err := h.key.GetIDPKeys(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.IDPKeyResponse, 0, len(secrets))
	for _, s := range secrets {
		resp = append(resp, dto.NewIDPKeyResponse(s))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) GetIDPKey(c *gin.Context) {
	idpType := c.Param("idp_type")
	tAppID := c.Param("t_app_id")
	secret, err := h.key.GetIDPKey(c.Request.Context(), idpType, tAppID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewIDPKeyResponse(secret))
}

func (h *Handler) CreateIDPKey(c *gin.Context) {
	var req dto.IDPKeyCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	secret, err := h.key.CreateIDPKey(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewIDPKeyResponse(secret))
}

func (h *Handler) UpdateIDPKey(c *gin.Context) {
	idpType := c.Param("idp_type")
	tAppID := c.Param("t_app_id")
	var req dto.IDPKeyUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.key.UpdateIDPKey(c.Request.Context(), idpType, tAppID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) DeleteIDPKey(c *gin.Context) {
	idpType := c.Param("idp_type")
	tAppID := c.Param("t_app_id")
	if err := h.key.DeleteIDPKey(c.Request.Context(), idpType, tAppID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// ==================== Domain IDP Config 相关 ====================

func (h *Handler) ListDomainIDPConfigs(c *gin.Context) {
	domainID := c.Param("domain_id")
	configs, err := h.provision.GetDomainIDPConfigs(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.DomainIDPConfigResponse, 0, len(configs))
	for _, cfg := range configs {
		resp = append(resp, dto.NewDomainIDPConfigResponse(cfg))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) GetDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	idpType := c.Param("idp_type")
	cfg, err := h.provision.GetDomainIDPConfig(c.Request.Context(), domainID, idpType)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewDomainIDPConfigResponse(cfg))
}

func (h *Handler) CreateDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.DomainIDPConfigCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := h.provision.CreateDomainIDPConfig(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewDomainIDPConfigResponse(cfg))
}

func (h *Handler) UpdateDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	idpType := c.Param("idp_type")
	var req dto.DomainIDPConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.provision.UpdateDomainIDPConfig(c.Request.Context(), domainID, idpType, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) DeleteDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	idpType := c.Param("idp_type")
	if err := h.provision.DeleteDomainIDPConfig(c.Request.Context(), domainID, idpType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

func (h *Handler) UpdateDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.DomainUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	domain, err := h.provision.UpdateDomain(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.DomainResponse{
		DomainID:    domain.DomainID,
		Name:        domain.Name,
		Description: domain.Description,
	})
}

func (h *Handler) ListDomains(c *gin.Context) {
	domains, err := h.provision.ListDomains(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.DomainResponse, 0, len(domains))
	for i := range domains {
		resp = append(resp, dto.DomainResponse{
			DomainID:    domains[i].DomainID,
			Name:        domains[i].Name,
			Description: domains[i].Description,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// ==================== Service 相关 ====================

func (h *Handler) ListServices(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	page, err := h.provision.ListServices(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pagination.Mapping(page, func(s *models.Service) dto.ServiceResponse {
		return dto.NewServiceResponse(s, domainID)
	}))
}

func (h *Handler) GetService(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.provision.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	c.JSON(http.StatusOK, dto.NewServiceResponse(service, domainID))
}

func (h *Handler) CreateService(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.ServiceCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.DomainID = domainID
	service, err := h.provision.CreateService(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewServiceResponse(service, domainID))
}

func (h *Handler) UpdateService(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.provision.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	var req dto.ServiceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.provision.UpdateService(c.Request.Context(), serviceID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) DeleteService(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.provision.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	if err := h.provision.DeleteService(c.Request.Context(), serviceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// ==================== Service Challenge Setting 相关 ====================

func (h *Handler) ListServiceChallengeSettings(c *gin.Context) {
	serviceID := c.Param("service_id")
	settings, err := h.provision.ListServiceChallengeSettings(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.ChallengeSettingResponse, 0, len(settings))
	for i := range settings {
		resp = append(resp, dto.NewChallengeSettingResponse(&settings[i]))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) GetServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	challengeType := c.Param("type")
	cfg, err := h.provision.GetServiceChallengeSetting(c.Request.Context(), serviceID, challengeType)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewChallengeSettingResponse(cfg))
}

func (h *Handler) CreateServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req dto.ChallengeSettingCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := h.provision.CreateServiceChallengeSetting(c.Request.Context(), serviceID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewChallengeSettingResponse(cfg))
}

func (h *Handler) UpdateServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	challengeType := c.Param("type")
	var req dto.ChallengeSettingUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.provision.UpdateServiceChallengeSetting(c.Request.Context(), serviceID, challengeType, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) DeleteServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	challengeType := c.Param("type")
	if err := h.provision.DeleteServiceChallengeSetting(c.Request.Context(), serviceID, challengeType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// ==================== Application 相关 ====================

func (h *Handler) ListApplications(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	page, err := h.provision.ListApplications(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pagination.Mapping(page, func(a *models.Application) dto.ApplicationResponse {
		return dto.NewApplicationResponse(a)
	}))
}

func (h *Handler) GetApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.provision.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	c.JSON(http.StatusOK, dto.NewApplicationResponse(app))
}

func (h *Handler) CreateApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.ApplicationCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.DomainID = domainID
	app, err := h.provision.CreateApplication(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewApplicationResponse(app))
}

func (h *Handler) UpdateApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.provision.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	var req dto.ApplicationUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.provision.UpdateApplication(c.Request.Context(), appID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) ListApplicationIDPConfigs(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.provision.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	configs, err := h.provision.GetApplicationIDPConfigs(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.ApplicationIDPConfigResponse, 0, len(configs))
	for _, cfg := range configs {
		resp = append(resp, dto.ApplicationIDPConfigResponse{
			AppID: cfg.AppID, Type: cfg.Type, Priority: cfg.Priority,
			Strategy: cfg.Strategy, TAppID: cfg.TAppID,
			CreatedAt: dto.FormatTime(cfg.CreatedAt), UpdatedAt: dto.FormatTime(cfg.UpdatedAt),
		})
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) CreateApplicationIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.provision.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	var req dto.ApplicationIDPConfigCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := h.provision.CreateApplicationIDPConfig(c.Request.Context(), appID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.ApplicationIDPConfigResponse{
		AppID: cfg.AppID, Type: cfg.Type, Priority: cfg.Priority,
		Strategy: cfg.Strategy, TAppID: cfg.TAppID,
		CreatedAt: dto.FormatTime(cfg.CreatedAt), UpdatedAt: dto.FormatTime(cfg.UpdatedAt),
	})
}

func (h *Handler) UpdateApplicationIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	idpType := c.Param("idp_type")
	app, err := h.provision.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	var req dto.ApplicationIDPConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.provision.UpdateApplicationIDPConfig(c.Request.Context(), appID, idpType, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) DeleteApplicationIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	idpType := c.Param("idp_type")
	app, err := h.provision.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	if err := h.provision.DeleteApplicationIDPConfig(c.Request.Context(), appID, idpType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

func (h *Handler) ListApplicationRelations(c *gin.Context) {
	appID := c.Param("app_id")
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	page, err := h.resource.ListApplicationRelations(c.Request.Context(), appID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pagination.Mapping(page, func(r *models.ApplicationServiceRelation) dto.ApplicationRelationResponse {
		return dto.NewApplicationRelationResponse(r)
	}))
}

// ==================== Relationship 相关（服务维度） ====================

func (h *Handler) ListRelationships(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	page, err := h.resource.ListRelationships(c.Request.Context(), serviceID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pagination.Mapping(page, func(r *models.Relationship) dto.RelationshipResponse {
		return dto.NewRelationshipResponse(r)
	}))
}

func (h *Handler) CreateRelationship(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req dto.RelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.ServiceID = serviceID
	rel, err := h.resource.CreateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewRelationshipResponse(rel))
}

func (h *Handler) UpdateRelationship(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req dto.RelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.ServiceID = serviceID
	rel, err := h.resource.UpdateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewRelationshipResponse(rel))
}

func (h *Handler) DeleteRelationship(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req dto.RelationshipDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.ServiceID = serviceID
	if err := h.resource.DeleteRelationship(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// ==================== Group 相关 ====================

func (h *Handler) CreateGroup(c *gin.Context) {
	var req dto.GroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	group, err := h.user.CreateGroup(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewGroupResponse(group))
}

func (h *Handler) GetGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	group, err := h.user.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewGroupResponse(group))
}

func (h *Handler) ListGroups(c *gin.Context) {
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	page, err := h.user.ListGroups(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pagination.Mapping(page, func(g *models.Group) dto.GroupResponse {
		return dto.NewGroupResponse(g)
	}))
}

func (h *Handler) UpdateGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	var req dto.GroupUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.user.UpdateGroup(c.Request.Context(), groupID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (h *Handler) SetGroupMembers(c *gin.Context) {
	groupID := c.Param("group_id")
	var req dto.GroupMemberRequest
	req.GroupID = groupID
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.user.SetGroupMembers(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "设置成功"})
}

func (h *Handler) GetGroupMembers(c *gin.Context) {
	groupID := c.Param("group_id")
	members, err := h.user.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.GroupMembersResponse{Members: members})
}
