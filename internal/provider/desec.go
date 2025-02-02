package provider

import (
	"context"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/nrdcg/desec"
)

type DesecClient struct {
	client *desec.Client
	ctx    context.Context
}

func CreateDesecClient(config config.Config) (*DesecClient, error) {
	ctx := context.Background()
	client := &DesecClient{
		client: desec.New(config.APIToken, desec.ClientOptions{}),
		ctx:    ctx,
	}
	return client, nil
}

func (d *DesecClient) GetDomains() ([]desec.Domain, error) {
	return d.client.Domains.GetAll(d.ctx)
}

func (d *DesecClient) GetRecords(domain string) ([]desec.RRSet, error) {
	return d.client.Records.GetAll(d.ctx, domain, nil)
}
