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
	provideHermesService,
	provideHermesHandler,
	provideAegisHandler,
	provideChaosHandler,
)

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

func provideHermesService() *hermes.Service {
	return hermes.NewService(hermesconfig.InitDB())
}

func provideAegisHandler(hermesService *hermes.Service) (*aegis.Handler, error) {
	hermesAdapter := adapter.NewHermesAdapter(hermesService)
	userAdapter := adapter.NewUserAdapter(hermesService)
	credentialStore := adapter.NewCredentialStoreAdapter(hermesService)
	credentialSvc := iris.NewCredentialService(credentialStore)
	return aegis.Initialize(hermesAdapter, userAdapter, credentialSvc)
}

func provideHermesHandler(hermesService *hermes.Service) *hermes.Handler {
	return hermes.NewHandler(hermesService)
}

func provideChaosHandler() (*chaos.Handler, error) {
	db := hermesconfig.InitDB()
	chaosModule, err := chaos.New(db)
	if err != nil {
		return nil, err
	}
	return chaosModule.Handler(), nil
}
