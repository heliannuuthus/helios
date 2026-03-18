package hermesclient

import (
	"google.golang.org/grpc"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
)

type Client struct {
	provision hermesv1.ProvisionServiceClient
	resource  hermesv1.ResourceServiceClient
	key       hermesv1.KeyServiceClient
	user      hermesv1.UserServiceClient
}

func New(conn grpc.ClientConnInterface) *Client {
	return &Client{
		provision: hermesv1.NewProvisionServiceClient(conn),
		resource:  hermesv1.NewResourceServiceClient(conn),
		key:       hermesv1.NewKeyServiceClient(conn),
		user:      hermesv1.NewUserServiceClient(conn),
	}
}
