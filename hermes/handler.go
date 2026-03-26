package hermes

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
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

// ==================== IDP Secret 相关 ====================

// ListIDPKeys GET /hermes/idp-keys
func (h *Handler) ListIDPKeys(c *gin.Context) {
	secrets, err := h.service.GetIDPKeys(c.Request.Context())
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

// GetIDPKey GET /hermes/idp-keys/:idp_type/:t_app_id
func (h *Handler) GetIDPKey(c *gin.Context) {
	idpType := c.Param("idp_type")
	tAppID := c.Param("t_app_id")
	secret, err := h.service.GetIDPKey(c.Request.Context(), idpType, tAppID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewIDPKeyResponse(secret))
}

// CreateIDPKey POST /hermes/idp-keys
func (h *Handler) CreateIDPKey(c *gin.Context) {
	var req dto.IDPKeyCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	secret, err := h.service.CreateIDPKey(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewIDPKeyResponse(secret))
}

// UpdateIDPKey PATCH /hermes/idp-keys/:idp_type/:t_app_id
func (h *Handler) UpdateIDPKey(c *gin.Context) {
	idpType := c.Param("idp_type")
	tAppID := c.Param("t_app_id")
	var req dto.IDPKeyUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.UpdateIDPKey(c.Request.Context(), idpType, tAppID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// DeleteIDPKey DELETE /hermes/idp-keys/:idp_type/:t_app_id
func (h *Handler) DeleteIDPKey(c *gin.Context) {
	idpType := c.Param("idp_type")
	tAppID := c.Param("t_app_id")
	if err := h.service.DeleteIDPKey(c.Request.Context(), idpType, tAppID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ==================== Domain IDP Config 相关 ====================

// ListDomainIDPConfigs GET /hermes/domains/:domain_id/idp-configs
func (h *Handler) ListDomainIDPConfigs(c *gin.Context) {
	domainID := c.Param("domain_id")
	configs, err := h.service.GetDomainIDPConfigs(c.Request.Context(), domainID)
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

// GetDomainIDPConfig GET /hermes/domains/:domain_id/idp-configs/:idp_type
func (h *Handler) GetDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	idpType := c.Param("idp_type")
	cfg, err := h.service.GetDomainIDPConfig(c.Request.Context(), domainID, idpType)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewDomainIDPConfigResponse(cfg))
}

// CreateDomainIDPConfig POST /hermes/domains/:domain_id/idp-configs
func (h *Handler) CreateDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.DomainIDPConfigCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := h.service.CreateDomainIDPConfig(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewDomainIDPConfigResponse(cfg))
}

// UpdateDomainIDPConfig PATCH /hermes/domains/:domain_id/idp-configs/:idp_type
func (h *Handler) UpdateDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	idpType := c.Param("idp_type")
	var req dto.DomainIDPConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.UpdateDomainIDPConfig(c.Request.Context(), domainID, idpType, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// DeleteDomainIDPConfig DELETE /hermes/domains/:domain_id/idp-configs/:idp_type
func (h *Handler) DeleteDomainIDPConfig(c *gin.Context) {
	domainID := c.Param("domain_id")
	idpType := c.Param("idp_type")
	if err := h.service.DeleteDomainIDPConfig(c.Request.Context(), domainID, idpType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// UpdateDomain PATCH /hermes/domains/:domain_id（仅 name、description 可编辑）
func (h *Handler) UpdateDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.DomainUpdateRequest
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
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	page, err := h.service.ListServices(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, pagination.Mapping(page, func(s *models.Service) dto.ServiceResponse {
		return dto.NewServiceResponse(s, domainID)
	}))
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
	c.JSON(http.StatusOK, dto.NewServiceResponse(service, domainID))
}

// CreateService POST /hermes/domains/:domain_id/services
func (h *Handler) CreateService(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.ServiceCreateRequest
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
	c.JSON(http.StatusOK, dto.NewServiceResponse(service, domainID))
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
	var req dto.ServiceUpdateRequest
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
	c.Status(http.StatusNoContent)
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
	var req dto.ServiceAppRelationsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.SetApplicationServiceRelations(c.Request.Context(), &dto.ApplicationServiceRelationRequest{
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
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	page, err := h.service.ListApplications(c.Request.Context(), domainID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, pagination.Mapping(page, func(a *models.Application) dto.ApplicationResponse {
		return dto.NewApplicationResponse(a)
	}))
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
	c.JSON(http.StatusOK, dto.NewApplicationResponse(app))
}

// CreateApplication POST /hermes/domains/:domain_id/applications
func (h *Handler) CreateApplication(c *gin.Context) {
	domainID := c.Param("domain_id")
	var req dto.ApplicationCreateRequest
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
	c.JSON(http.StatusOK, dto.NewApplicationResponse(app))
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
	var req dto.ApplicationUpdateRequest
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
			TAppID:    cfg.TAppID,
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
	var req dto.ApplicationIDPConfigCreateRequest
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
		TAppID:    cfg.TAppID,
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
	var req dto.ApplicationIDPConfigUpdateRequest
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
	c.Status(http.StatusNoContent)
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

// DeleteDomain DELETE /hermes/domains/:domain_id
func (h *Handler) DeleteDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	if err := h.service.DeleteDomain(c.Request.Context(), domainID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// DeleteApplication DELETE /hermes/domains/:domain_id/applications/:app_id
func (h *Handler) DeleteApplication(c *gin.Context) {
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
	if err := h.service.DeleteApplication(c.Request.Context(), appID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// DeleteGroup DELETE /hermes/groups/:group_id
func (h *Handler) DeleteGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	if err := h.service.DeleteGroup(c.Request.Context(), groupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ==================== Service Challenge Setting 相关 ====================

// ListServiceChallengeSettings GET /hermes/domains/:domain_id/services/:service_id/challenge-settings
func (h *Handler) ListServiceChallengeSettings(c *gin.Context) {
	serviceID := c.Param("service_id")
	settings, err := h.service.ListServiceChallengeSettings(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.ServiceChallengeSettingResponse, 0, len(settings))
	for i := range settings {
		resp = append(resp, dto.NewServiceChallengeSettingResponse(&settings[i]))
	}
	c.JSON(http.StatusOK, resp)
}

// CreateServiceChallengeSetting POST /hermes/domains/:domain_id/services/:service_id/challenge-settings
func (h *Handler) CreateServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req dto.ServiceChallengeSettingCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	setting, err := h.service.CreateServiceChallengeSetting(c.Request.Context(), serviceID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.NewServiceChallengeSettingResponse(setting))
}

// UpdateServiceChallengeSetting PATCH /hermes/domains/:domain_id/services/:service_id/challenge-settings/:type
func (h *Handler) UpdateServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	challengeType := c.Param("type")
	var req dto.ServiceChallengeSettingUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.UpdateServiceChallengeSetting(c.Request.Context(), serviceID, challengeType, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// DeleteServiceChallengeSetting DELETE /hermes/domains/:domain_id/services/:service_id/challenge-settings/:type
func (h *Handler) DeleteServiceChallengeSetting(c *gin.Context) {
	serviceID := c.Param("service_id")
	challengeType := c.Param("type")
	if err := h.service.DeleteServiceChallengeSetting(c.Request.Context(), serviceID, challengeType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ==================== Relationship 相关 ====================

// CreateRelationship POST /hermes/relationships
func (h *Handler) CreateRelationship(c *gin.Context) {
	var req dto.RelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.CreateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.NewRelationshipResponse(rel))
}

// DeleteRelationship DELETE /hermes/relationships
func (h *Handler) DeleteRelationship(c *gin.Context) {
	var req dto.RelationshipDeleteRequest
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
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	page, err := h.service.ListRelationships(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, pagination.Mapping(page, func(r *models.Relationship) dto.RelationshipResponse {
		return dto.NewRelationshipResponse(r)
	}))
}

// UpdateRelationship PATCH /hermes/relationships
func (h *Handler) UpdateRelationship(c *gin.Context) {
	var req dto.RelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.UpdateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.NewRelationshipResponse(rel))
}

// ==================== App Service Relationship 相关（RESTful 风格）====================

// ListAppServiceRelationships GET /hermes/applications/:app_id/services/:service_id/relationships
func (h *Handler) ListAppServiceRelationships(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")

	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	page, err := h.service.ListAppServiceRelationships(c.Request.Context(), appID, serviceID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, pagination.Mapping(page, func(r *models.Relationship) dto.RelationshipResponse {
		return dto.NewRelationshipResponse(r)
	}))
}

// CreateAppServiceRelationship POST /hermes/applications/:app_id/services/:service_id/relationships
func (h *Handler) CreateAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")

	var req dto.AppServiceRelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.CreateAppServiceRelationship(c.Request.Context(), appID, serviceID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, dto.NewRelationshipResponse(rel))
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

	var req dto.AppServiceRelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.UpdateAppServiceRelationship(c.Request.Context(), appID, serviceID, uint(relationshipID), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.NewRelationshipResponse(rel))
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
	var req dto.GroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group, err := h.service.CreateGroup(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.NewGroupResponse(group))
}

// GetGroup GET /hermes/groups/:group_id
func (h *Handler) GetGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	group, err := h.service.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.NewGroupResponse(group))
}

// ListGroups GET /hermes/groups
func (h *Handler) ListGroups(c *gin.Context) {
	var req dto.ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	page, err := h.service.ListGroups(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, pagination.Mapping(page, func(g *models.Group) dto.GroupResponse {
		return dto.NewGroupResponse(g)
	}))
}

// UpdateGroup PATCH /hermes/groups/:group_id
func (h *Handler) UpdateGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	var req dto.GroupUpdateRequest
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
	var req dto.GroupMemberRequest
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
