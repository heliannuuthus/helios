package hermes

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
)

// Handler 管理服务处理器
type Handler struct {
	service *Service
}

// NewHandler 创建管理服务处理器
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// ==================== Domain 相关 ====================

// GetDomain GET /hermes/domains/:domain_id
func (h *Handler) GetDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	domain, err := h.service.GetDomain(c.Request.Context(), domainID)
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

// GetDomainAllowedIDPs GET /hermes/domains/:domain_id/idps（供配置应用 IDP 时按需拉取）
func (h *Handler) GetDomainAllowedIDPs(c *gin.Context) {
	domainID := c.Param("domain_id")
	idps, err := h.service.GetDomainAllowedIDPs(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"allowed_idps": idps})
}

// UpdateDomain PATCH /hermes/domains/:domain_id（仅 name、description 可编辑）
func (h *Handler) UpdateDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req DomainUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	domain, err := h.service.UpdateDomain(c.Request.Context(), domainID, &req)
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

// ListDomains GET /hermes/domains
func (h *Handler) ListDomains(c *gin.Context) {
	domains, err := h.service.ListDomains(c.Request.Context())
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

// ==================== Service 相关（均挂载在 domains/:domain_id/services 下） ====================

// ListServices GET /hermes/domains/:domain_id/services
func (h *Handler) ListServices(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Query("service_id")
	name := strings.TrimSpace(c.Query("name"))
	services, err := h.service.ListServices(c.Request.Context(), domainID, serviceID, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.ServiceResponse, 0, len(services))
	for i := range services {
		s := &services[i]
		effectiveDomainID := s.DomainID
		if effectiveDomainID == models.CrossDomainID {
			effectiveDomainID = domainID
		}
		resp = append(resp, dto.ServiceResponse{
			ServiceID:            s.ServiceID,
			DomainID:             effectiveDomainID,
			Name:                 s.Name,
			Description:          s.Description,
			LogoURL:              s.LogoURL,
			AccessTokenExpiresIn: s.AccessTokenExpiresIn,
			CreatedAt:            dto.FormatTime(s.CreatedAt),
			UpdatedAt:            dto.FormatTime(s.UpdatedAt),
		})
	}
	c.JSON(http.StatusOK, resp)
}

// GetService GET /hermes/domains/:domain_id/services/:service_id
func (h *Handler) GetService(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	effectiveDomainID := service.DomainID
	if effectiveDomainID == models.CrossDomainID {
		effectiveDomainID = domainID
	}
	c.JSON(http.StatusOK, dto.ServiceResponse{
		ServiceID:            service.ServiceID,
		DomainID:             effectiveDomainID,
		Name:                 service.Name,
		Description:          service.Description,
		LogoURL:              service.LogoURL,
		AccessTokenExpiresIn: service.AccessTokenExpiresIn,
		CreatedAt:            dto.FormatTime(service.CreatedAt),
		UpdatedAt:            dto.FormatTime(service.UpdatedAt),
	})
}

// CreateService POST /hermes/domains/:domain_id/services
func (h *Handler) CreateService(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req ServiceCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.DomainID = domainID
	service, err := h.service.CreateService(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.ServiceResponse{
		ServiceID:            service.ServiceID,
		DomainID:             service.DomainID,
		Name:                 service.Name,
		Description:          service.Description,
		LogoURL:              service.LogoURL,
		AccessTokenExpiresIn: service.AccessTokenExpiresIn,
		CreatedAt:            dto.FormatTime(service.CreatedAt),
		UpdatedAt:            dto.FormatTime(service.UpdatedAt),
	})
}

// UpdateService PATCH /hermes/domains/:domain_id/services/:service_id
func (h *Handler) UpdateService(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	var req ServiceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.UpdateService(c.Request.Context(), serviceID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// DeleteService DELETE /hermes/domains/:domain_id/services/:service_id
func (h *Handler) DeleteService(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	if err := h.service.DeleteService(c.Request.Context(), serviceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// GetServiceApplicationRelations GET /hermes/domains/:domain_id/services/:service_id/applications
func (h *Handler) GetServiceApplicationRelations(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	relations, err := h.service.GetServiceApplicationRelations(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	byApp := make(map[string][]string)
	for i := range relations {
		aid := relations[i].AppID
		byApp[aid] = append(byApp[aid], relations[i].Relation)
	}
	resp := make([]dto.ServiceApplicationRelationResponse, 0, len(byApp))
	for aid, rels := range byApp {
		resp = append(resp, dto.ServiceApplicationRelationResponse{AppID: aid, Relations: rels})
	}
	c.JSON(http.StatusOK, resp)
}

// GetServiceAppRelations GET /hermes/domains/:domain_id/services/:service_id/applications/:app_id/relations
func (h *Handler) GetServiceAppRelations(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	appID := c.Param("app_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	rels, err := h.service.GetServiceAppRelations(c.Request.Context(), serviceID, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"relations": rels})
}

// SetServiceAppRelations PUT /hermes/domains/:domain_id/services/:service_id/applications/:app_id/relations
func (h *Handler) SetServiceAppRelations(c *gin.Context) {
	domainID := c.Param("domain_id")
	serviceID := c.Param("service_id")
	appID := c.Param("app_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if service.DomainID != domainID && service.DomainID != models.CrossDomainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found in this domain"})
		return
	}
	var req ServiceAppRelationsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.SetApplicationServiceRelations(c.Request.Context(), &ApplicationServiceRelationRequest{
		AppID: appID, ServiceID: serviceID, Relations: req.Relations,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "设置成功"})
}

// ==================== Application 相关（均挂载在 domains/:domain_id/applications 下） ====================

// ListApplications GET /hermes/domains/:domain_id/applications
func (h *Handler) ListApplications(c *gin.Context) {
	domainID := c.Param("domain_id")
	apps, err := h.service.ListApplications(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.ApplicationResponse, 0, len(apps))
	for i := range apps {
		a := &apps[i]
		resp = append(resp, dto.ApplicationResponse{
			DomainID:                      a.DomainID,
			AppID:                         a.AppID,
			Name:                          a.Name,
			Description:                   a.Description,
			LogoURL:                       a.LogoURL,
			AllowedRedirectURIs:           dto.ParseJSONStringSlice(a.AllowedRedirectURIs),
			AllowedOrigins:                dto.ParseJSONStringSlice(a.AllowedOrigins),
			AllowedLogoutURIs:             dto.ParseJSONStringSlice(a.AllowedLogoutURIs),
			IDTokenExpiresIn:              a.IDTokenExpiresIn,
			RefreshTokenExpiresIn:         a.RefreshTokenExpiresIn,
			RefreshTokenAbsoluteExpiresIn: a.RefreshTokenAbsoluteExpiresIn,
			CreatedAt:                     dto.FormatTime(a.CreatedAt),
			UpdatedAt:                     dto.FormatTime(a.UpdatedAt),
		})
	}
	c.JSON(http.StatusOK, resp)
}

// GetApplication GET /hermes/domains/:domain_id/applications/:app_id
func (h *Handler) GetApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	c.JSON(http.StatusOK, dto.ApplicationResponse{
		DomainID:                      app.DomainID,
		AppID:                         app.AppID,
		Name:                          app.Name,
		Description:                   app.Description,
		LogoURL:                       app.LogoURL,
		AllowedRedirectURIs:           dto.ParseJSONStringSlice(app.AllowedRedirectURIs),
		AllowedOrigins:                dto.ParseJSONStringSlice(app.AllowedOrigins),
		AllowedLogoutURIs:             dto.ParseJSONStringSlice(app.AllowedLogoutURIs),
		IDTokenExpiresIn:              app.IDTokenExpiresIn,
		RefreshTokenExpiresIn:         app.RefreshTokenExpiresIn,
		RefreshTokenAbsoluteExpiresIn: app.RefreshTokenAbsoluteExpiresIn,
		CreatedAt:                     dto.FormatTime(app.CreatedAt),
		UpdatedAt:                     dto.FormatTime(app.UpdatedAt),
	})
}

// CreateApplication POST /hermes/domains/:domain_id/applications
func (h *Handler) CreateApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req ApplicationCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.DomainID = domainID
	app, err := h.service.CreateApplication(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.ApplicationResponse{
		DomainID:                      app.DomainID,
		AppID:                         app.AppID,
		Name:                          app.Name,
		Description:                   app.Description,
		LogoURL:                       app.LogoURL,
		AllowedRedirectURIs:           dto.ParseJSONStringSlice(app.AllowedRedirectURIs),
		AllowedOrigins:                dto.ParseJSONStringSlice(app.AllowedOrigins),
		AllowedLogoutURIs:             dto.ParseJSONStringSlice(app.AllowedLogoutURIs),
		IDTokenExpiresIn:              app.IDTokenExpiresIn,
		RefreshTokenExpiresIn:         app.RefreshTokenExpiresIn,
		RefreshTokenAbsoluteExpiresIn: app.RefreshTokenAbsoluteExpiresIn,
		CreatedAt:                     dto.FormatTime(app.CreatedAt),
		UpdatedAt:                     dto.FormatTime(app.UpdatedAt),
	})
}

// UpdateApplication PATCH /hermes/domains/:domain_id/applications/:app_id
func (h *Handler) UpdateApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	var req ApplicationUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.UpdateApplication(c.Request.Context(), appID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// ListApplicationIDPConfigs GET /hermes/domains/:domain_id/applications/:app_id/idp-configs
func (h *Handler) ListApplicationIDPConfigs(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	configs, err := h.service.GetApplicationIDPConfigs(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.ApplicationIDPConfigResponse, 0, len(configs))
	for _, cfg := range configs {
		resp = append(resp, dto.ApplicationIDPConfigResponse{
			AppID:     cfg.AppID,
			Type:      cfg.Type,
			Priority:  cfg.Priority,
			Strategy:  cfg.Strategy,
			Delegate:  cfg.Delegate,
			Require:   cfg.Require,
			CreatedAt: dto.FormatTime(cfg.CreatedAt),
			UpdatedAt: dto.FormatTime(cfg.UpdatedAt),
		})
	}
	c.JSON(http.StatusOK, resp)
}

// CreateApplicationIDPConfig POST /hermes/domains/:domain_id/applications/:app_id/idp-configs（仅允许域下 IDP）
func (h *Handler) CreateApplicationIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	var req ApplicationIDPConfigCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := h.service.CreateApplicationIDPConfig(c.Request.Context(), appID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.ApplicationIDPConfigResponse{
		AppID:     cfg.AppID,
		Type:      cfg.Type,
		Priority:  cfg.Priority,
		Strategy:  cfg.Strategy,
		Delegate:  cfg.Delegate,
		Require:   cfg.Require,
		CreatedAt: dto.FormatTime(cfg.CreatedAt),
		UpdatedAt: dto.FormatTime(cfg.UpdatedAt),
	})
}

// UpdateApplicationIDPConfig PATCH /hermes/domains/:domain_id/applications/:app_id/idp-configs/:idp_type
func (h *Handler) UpdateApplicationIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	idpType := c.Param("idp_type")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	var req ApplicationIDPConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.UpdateApplicationIDPConfig(c.Request.Context(), appID, idpType, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// DeleteApplicationIDPConfig DELETE /hermes/domains/:domain_id/applications/:app_id/idp-configs/:idp_type
func (h *Handler) DeleteApplicationIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	idpType := c.Param("idp_type")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	if err := h.service.DeleteApplicationIDPConfig(c.Request.Context(), appID, idpType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// GetApplicationServiceRelations GET /hermes/domains/:domain_id/applications/:app_id/relations
func (h *Handler) GetApplicationServiceRelations(c *gin.Context) {
	domainID := c.Param("domain_id")
	appID := c.Param("app_id")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if app.DomainID != domainID {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found in this domain"})
		return
	}
	relations, err := h.service.GetApplicationServiceRelations(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	byService := make(map[string][]string)
	for i := range relations {
		sid := relations[i].ServiceID
		byService[sid] = append(byService[sid], relations[i].Relation)
	}
	resp := make([]dto.ApplicationServiceRelationResponse, 0, len(byService))
	for sid, rels := range byService {
		resp = append(resp, dto.ApplicationServiceRelationResponse{ServiceID: sid, Relations: rels})
	}
	c.JSON(http.StatusOK, resp)
}

// ==================== Relationship 相关 ====================

// CreateRelationship POST /hermes/relationships
func (h *Handler) CreateRelationship(c *gin.Context) {
	var req RelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.CreateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, buildRelationshipResponse(rel))
}

// DeleteRelationship DELETE /hermes/relationships
func (h *Handler) DeleteRelationship(c *gin.Context) {
	var req RelationshipDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.DeleteRelationship(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// ListRelationships GET /hermes/relationships
func (h *Handler) ListRelationships(c *gin.Context) {
	serviceID := c.Query("service_id")
	subjectType := c.Query("subject_type")
	subjectID := c.Query("subject_id")

	rels, err := h.service.ListRelationships(c.Request.Context(), serviceID, subjectType, subjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := make([]dto.RelationshipResponse, 0, len(rels))
	for i := range rels {
		resp = append(resp, buildRelationshipResponse(&rels[i]))
	}
	c.JSON(http.StatusOK, resp)
}

// UpdateRelationship PATCH /hermes/relationships
func (h *Handler) UpdateRelationship(c *gin.Context) {
	var req RelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.UpdateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, buildRelationshipResponse(rel))
}

// ==================== App Service Relationship 相关（RESTful 风格）====================

// ListAppServiceRelationships GET /hermes/applications/:app_id/services/:service_id/relationships
func (h *Handler) ListAppServiceRelationships(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")
	subjectType := c.Query("subject_type")
	subjectID := c.Query("subject_id")

	rels, err := h.service.ListAppServiceRelationships(c.Request.Context(), appID, serviceID, subjectType, subjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := make([]dto.RelationshipResponse, 0, len(rels))
	for i := range rels {
		resp = append(resp, buildRelationshipResponse(&rels[i]))
	}
	c.JSON(http.StatusOK, resp)
}

// CreateAppServiceRelationship POST /hermes/applications/:app_id/services/:service_id/relationships
func (h *Handler) CreateAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")

	var req AppServiceRelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.CreateAppServiceRelationship(c.Request.Context(), appID, serviceID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, buildRelationshipResponse(rel))
}

// UpdateAppServiceRelationship PATCH /hermes/applications/:app_id/services/:service_id/relationships/:relationship_id
func (h *Handler) UpdateAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")
	relationshipIDStr := c.Param("relationship_id")

	relationshipID, err := strconv.ParseUint(relationshipIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid relationship_id"})
		return
	}

	var req AppServiceRelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.UpdateAppServiceRelationship(c.Request.Context(), appID, serviceID, uint(relationshipID), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, buildRelationshipResponse(rel))
}

// DeleteAppServiceRelationship DELETE /hermes/applications/:app_id/services/:service_id/relationships/:relationship_id
func (h *Handler) DeleteAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")
	relationshipIDStr := c.Param("relationship_id")

	relationshipID, err := strconv.ParseUint(relationshipIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid relationship_id"})
		return
	}

	if err := h.service.DeleteAppServiceRelationship(c.Request.Context(), appID, serviceID, uint(relationshipID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// ==================== Group 相关 ====================

// CreateGroup POST /hermes/groups
func (h *Handler) CreateGroup(c *gin.Context) {
	var req GroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group, err := h.service.CreateGroup(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, buildGroupResponse(group))
}

// GetGroup GET /hermes/groups/:group_id
func (h *Handler) GetGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	group, err := h.service.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, buildGroupResponse(group))
}

// ListGroups GET /hermes/groups
func (h *Handler) ListGroups(c *gin.Context) {
	groups, err := h.service.ListGroups(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := make([]dto.GroupResponse, 0, len(groups))
	for i := range groups {
		resp = append(resp, buildGroupResponse(&groups[i]))
	}
	c.JSON(http.StatusOK, resp)
}

// UpdateGroup PATCH /hermes/groups/:group_id
func (h *Handler) UpdateGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	var req GroupUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.UpdateGroup(c.Request.Context(), groupID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// SetGroupMembers POST /hermes/groups/:group_id/members
func (h *Handler) SetGroupMembers(c *gin.Context) {
	groupID := c.Param("group_id")
	var req GroupMemberRequest
	req.GroupID = groupID
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.SetGroupMembers(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "设置成功"})
}

// GetGroupMembers GET /hermes/groups/:group_id/members
func (h *Handler) GetGroupMembers(c *gin.Context) {
	groupID := c.Param("group_id")
	members, err := h.service.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.GroupMembersResponse{Members: members})
}

// buildRelationshipResponse 根据 model 直接构建响应（无 _id，expires_at 格式化为 ISO）
func buildRelationshipResponse(r *models.Relationship) dto.RelationshipResponse {
	resp := dto.RelationshipResponse{
		ServiceID:   r.ServiceID,
		SubjectType: r.SubjectType,
		SubjectID:   r.SubjectID,
		Relation:    r.Relation,
		ObjectType:  r.ObjectType,
		ObjectID:    r.ObjectID,
		CreatedAt:   dto.FormatTime(r.CreatedAt),
	}
	if r.ExpiresAt != nil {
		s := dto.FormatTime(*r.ExpiresAt)
		resp.ExpiresAt = &s
	}
	return resp
}

// buildGroupResponse 根据 model 直接构建响应（无 _id）
func buildGroupResponse(g *models.Group) dto.GroupResponse {
	return dto.GroupResponse{
		GroupID:     g.GroupID,
		ServiceID:   g.ServiceID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   dto.FormatTime(g.CreatedAt),
		UpdatedAt:   dto.FormatTime(g.UpdatedAt),
	}
}
