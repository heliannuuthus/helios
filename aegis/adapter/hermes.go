package adapter

import (
	"context"

	amodels "github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/hermes"
)

// HermesAdapter 将 hermes 域服务适配为 contract.HermesProvider
type HermesAdapter struct {
	provision *hermes.ProvisionService
	key       *hermes.KeyService
	resource  *hermes.ResourceService
}

func NewHermesAdapter(ps *hermes.ProvisionService, ks *hermes.KeyService, rs *hermes.ResourceService) *HermesAdapter {
	return &HermesAdapter{provision: ps, key: ks, resource: rs}
}

func (a *HermesAdapter) GetDomain(ctx context.Context, domainID string) (*amodels.Domain, error) {
	d, err := a.provision.GetDomain(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return ConvertDomain(d), nil
}

func (a *HermesAdapter) GetApplication(ctx context.Context, appID string) (*amodels.Application, error) {
	app, err := a.provision.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}
	return ConvertApplication(app), nil
}

func (a *HermesAdapter) GetService(ctx context.Context, serviceID string) (*amodels.Service, error) {
	svc, err := a.provision.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	return ConvertService(svc), nil
}

func (a *HermesAdapter) GetDomainKeys(ctx context.Context, domainID string) ([][]byte, error) {
	return a.key.GetDomainKeys(ctx, domainID)
}

func (a *HermesAdapter) GetDomainIDPConfigs(ctx context.Context, domainID string) ([]*amodels.DomainIDPConfig, error) {
	cs, err := a.provision.GetDomainIDPConfigs(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return ConvertDomainIDPConfigs(cs), nil
}

func (a *HermesAdapter) GetApplicationKeys(ctx context.Context, appID string) ([][]byte, error) {
	return a.key.GetApplicationKeys(ctx, appID)
}

func (a *HermesAdapter) GetServiceKeys(ctx context.Context, serviceID string) ([][]byte, error) {
	return a.key.GetServiceKeys(ctx, serviceID)
}

func (a *HermesAdapter) GetApplicationServiceRelations(ctx context.Context, appID string) ([]amodels.ApplicationServiceRelation, error) {
	rs, err := a.resource.FindApplicationRelations(ctx, appID)
	if err != nil {
		return nil, err
	}
	return ConvertRelations(rs), nil
}

func (a *HermesAdapter) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*amodels.ApplicationIDPConfig, error) {
	cs, err := a.provision.GetApplicationIDPConfigs(ctx, appID)
	if err != nil {
		return nil, err
	}
	return ConvertIDPConfigs(cs), nil
}

func (a *HermesAdapter) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*amodels.ServiceChallengeSetting, error) {
	c, err := a.provision.GetServiceChallengeSetting(ctx, serviceID, challengeType)
	if err != nil {
		return nil, err
	}
	return ConvertChallengeSettingPtr(c), nil
}

func (a *HermesAdapter) FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]amodels.Relationship, error) {
	rs, err := a.resource.FindRelationships(ctx, serviceID, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	return ConvertRelationships(rs), nil
}

func (a *HermesAdapter) ResolveIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error) {
	return a.key.ResolveIDPKey(ctx, appID, idpType)
}
