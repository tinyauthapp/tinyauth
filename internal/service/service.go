package service

import (
	"context"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type Services struct {
	AccessControlService *AccessControlsService
	AuthService          *AuthService
	DockerService        *DockerService
	KubernetesService    *KubernetesService
	LDAPService          *LdapService
	OAuthBrokerService   *OAuthBrokerService
	OIDCService          *OIDCService
	TailscaleService     *TailscaleService
	PolicyEngine         *PolicyEngine
}

type ServiceDependencies struct {
	Log           *logger.Logger
	StaticConfig  *model.Config
	RuntimeConfig *model.RuntimeConfig
	Ctx           context.Context
	Ding          *ding.Ding
	Services      *Services
	LabelProvider LabelProvider
	Queries       *repository.Store
}
