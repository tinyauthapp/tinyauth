package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:generate controller-gen object paths=$GOFILE
//go:generate controller-gen rbac:roleName=tinyauth crd paths=./... output:crd:dir=./crds output:stdout

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Application is a set of access control rules that can be applied to a
// specific domain. It is an alternative to environment variable or config-based
// access controls.
type Application struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ApplicationSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen=true

// ApplicationSpec describes the application to which this rule applies to
type ApplicationSpec struct {
	Config   AppConfig   `json:"config,omitempty"`
	Users    AppUsers    `json:"users,omitempty"`
	OAuth    AppOAuth    `json:"oauth,omitempty"`
	IP       AppIP       `json:"ip,omitempty"`
	Response AppResponse `json:"response,omitempty"`
	Path     AppPath     `json:"path,omitempty"`
	LDAP     AppLDAP     `json:"ldap,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppConfig specifies configuration for the application
type AppConfig struct {
	// +required
	Domain string `json:"domain,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppUsers specifies user access control rules
type AppUsers struct {
	Allow string `json:"allow,omitempty"`
	Block string `json:"block,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppOAuth specifies OAuth access control rules
type AppOAuth struct {
	Whitelist string `json:"whitelist,omitempty"`
	Groups    string `json:"groups,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppLDAP specifies LDAP access control rules
type AppLDAP struct {
	Groups string `json:"groups,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppIP specifies IP access control rules
type AppIP struct {
	Allow  []string `json:"allow,omitempty"`
	Block  []string `json:"block,omitempty"`
	Bypass []string `json:"bypass,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppResponse specifies response headers and basic auth credentials
type AppResponse struct {
	Headers   []string     `json:"headers,omitempty"`
	BasicAuth AppBasicAuth `json:"basicAuth,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppBasicAuth specifies basic auth credentials
type AppBasicAuth struct {
	Username          string                    `json:"username,omitempty"`
	PasswordSecretRef *corev1.SecretKeySelector `json:"passwordSecretRef,omitempty"`
}

// +k8s:deepcopy-gen=true

// AppPath specifies path-based access control rules
type AppPath struct {
	Allow string `json:"allow,omitempty"`
	Block string `json:"block,omitempty"`
}
