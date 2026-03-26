package adapter

import (
	"context"

	amodels "github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/hermes"
)

// HermesAdapter 将 hermes.Service 适配为 contract.HermesProvider
type HermesAdapter struct {
	svc *hermes.Service
}

func NewHermesAdapter(svc *hermes.Service) *HermesAdapter {
	return &HermesAdapter{svc: svc}
}

func (a *HermesAdapter) GetDomain(ctx context.Context, domainID string) (*amodels.Domain, error) {
	d, err := a.svc.GetDomain(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return ConvertDomain(d), nil
}

func (a *HermesAdapter) GetDomainIDPConfigs(ctx context.Context, domainID string) ([]*amodels.DomainIDPConfig, error) {
	cs, err := a.svc.GetDomainIDPConfigs(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return ConvertDomainIDPConfigs(cs), nil
}

func (a *HermesAdapter) GetApplication(ctx context.Context, appID string) (*amodels.Application, error) {
	app, err := a.svc.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}
	return ConvertApplication(app), nil
}

func (a *HermesAdapter) GetService(ctx context.Context, serviceID string) (*amodels.Service, error) {
	svc, err := a.svc.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	return ConvertService(svc), nil
}

func (a *HermesAdapter) GetDomainKeys(ctx context.Context, domainID string) ([][]byte, error) {
	return a.svc.GetDomainKeys(ctx, domainID)
}

func (a *HermesAdapter) GetApplicationKeys(ctx context.Context, appID string) ([][]byte, error) {
	return a.svc.GetApplicationKeys(ctx, appID)
}

func (a *HermesAdapter) GetServiceKeys(ctx context.Context, serviceID string) ([][]byte, error) {
	return a.svc.GetServiceKeys(ctx, serviceID)
}

func (a *HermesAdapter) GetApplicationServiceRelations(ctx context.Context, appID string) ([]amodels.ApplicationServiceRelation, error) {
	rs, err := a.svc.GetApplicationServiceRelations(ctx, appID)
	if err != nil {
		return nil, err
	}
	return ConvertRelations(rs), nil
}

func (a *HermesAdapter) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*amodels.ApplicationIDPConfig, error) {
	cs, err := a.svc.GetApplicationIDPConfigs(ctx, appID)
	if err != nil {
		return nil, err
	}
	return ConvertIDPConfigs(cs), nil
}

func (a *HermesAdapter) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*amodels.ServiceChallengeSetting, error) {
	c, err := a.svc.GetServiceChallengeSetting(ctx, serviceID, challengeType)
	if err != nil {
		return nil, err
	}
	return ConvertChallengeSettingPtr(c), nil
}

func (a *HermesAdapter) FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]amodels.Relationship, error) {
	rs, err := a.svc.FindRelationships(ctx, serviceID, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	return ConvertRelationships(rs), nil
}

func (a *HermesAdapter) ResolveIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error) {
	return a.svc.ResolveIDPKey(ctx, appID, idpType)
}
