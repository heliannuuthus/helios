//go:build wireinject

package main

import (
	"github.com/google/wire"

	"github.com/heliannuuthus/helios/aegis"
	"github.com/heliannuuthus/helios/aegis/adapter"
	"github.com/heliannuuthus/helios/chaos"
	"github.com/heliannuuthus/helios/hermes"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/iris"
	"github.com/heliannuuthus/helios/zwei"
	zweiconfig "github.com/heliannuuthus/helios/zwei/config"
)

var ProviderSet = wire.NewSet(
	provideZwei,
	provideHermesServices,
	provideHermesHandler,
	provideAegisHandler,
	provideChaosHandler,
)

type HermesServices struct {
	User      *hermes.UserService
	Provision *hermes.ProvisionService
	Resource  *hermes.ResourceService
	Key       *hermes.KeyService
}

type App struct {
	Zwei          *zwei.Zwei
	AegisHandler  *aegis.Handler
	HermesHandler *hermes.Handler
	ChaosHandler  *chaos.Handler
}

func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}

func provideZwei() *zwei.Zwei {
	return zwei.New(zweiconfig.InitDB())
}

func provideHermesServices() *HermesServices {
	db := hermesconfig.InitDB()
	keySvc := hermes.NewKeyService(db)
	return &HermesServices{
		User:      hermes.NewUserService(db),
		Provision: hermes.NewProvisionService(db, keySvc),
		Resource:  hermes.NewResourceService(db),
		Key:       keySvc,
	}
}

func provideAegisHandler(svc *HermesServices) (*aegis.Handler, error) {
	hermesAdapter := adapter.NewHermesAdapter(svc.Provision, svc.Key, svc.Resource)
	userAdapter := adapter.NewUserAdapter(svc.User)
	credentialStore := adapter.NewCredentialStoreAdapter(svc.User)
	credentialSvc := iris.NewCredentialService(credentialStore)
	return aegis.Initialize(hermesAdapter, userAdapter, credentialSvc)
}

func provideHermesHandler(svc *HermesServices) *hermes.Handler {
	return hermes.NewHandler(svc.Provision, svc.Resource, svc.Key, svc.User)
}

func provideChaosHandler() (*chaos.Handler, error) {
	db := hermesconfig.InitDB()
	chaosModule, err := chaos.New(db)
	if err != nil {
		return nil, err
	}
	return chaosModule.Handler(), nil
}
