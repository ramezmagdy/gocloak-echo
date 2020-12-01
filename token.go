package gocloakecho

import (
	"github.com/Nerzal/gocloak/v7/pkg/jwx"
	"github.com/dgrijalva/jwt-go"
)

// Authenticate holds authentication information
type Authenticate struct {
	ClientID     string  `json:"clientID"`
	ClientSecret string  `json:"clientSecret"`
	Realm        string  `json:"realm,omitempty"`
	Scope        string  `json:"scope,omitempty"`
	UserName     *string `json:"username,omitempty"`
	Password     *string `json:"password,omitempty"`
}

// Refresh is used to refresh the JWT
type Refresh struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	Realm        string `json:"realm,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

type RequestModeEnum string

const (
	PermissionRequestMode RequestModeEnum = "permission"
	DecisionRequestMode   RequestModeEnum = "decision"
)

type EnforcerConfig struct {
	Audience     string
	Permissions  *[]string
	ResponseMode *RequestModeEnum
}

// JWT is a JWT
type JWT struct {
	AccessToken      string `json:"accessToken"`
	ExpiresIn        int    `json:"expiresIn"`
	RefreshExpiresIn int    `json:"refreshExpiresIn"`
	RefreshToken     string `json:"refreshToken"`
	TokenType        string `json:"tokenType"`
	NotBeforePolicy  int    `json:"notBeforePolicy"`
	SessionState     string `json:"sessionState"`
	Scope            string `json:"scope"`
}

type Claims struct {
	jwt.StandardClaims
	Typ               string             `json:"typ,omitempty"`
	Azp               string             `json:"azp,omitempty"`
	AuthTime          int                `json:"auth_time,omitempty"`
	SessionState      string             `json:"session_state,omitempty"`
	Acr               string             `json:"acr,omitempty"`
	AllowedOrigins    []string           `json:"allowed-origins,omitempty"`
	RealmAccess       jwx.RealmAccess    `json:"realm_access,omitempty"`
	ResourceAccess    jwx.ResourceAccess `json:"resource_access,omitempty"`
	Scope             string             `json:"scope,omitempty"`
	EmailVerified     bool               `json:"email_verified,omitempty"`
	Address           jwx.Address        `json:"address,omitempty"`
	Name              string             `json:"name,omitempty"`
	PreferredUsername string             `json:"preferred_username,omitempty"`
	GivenName         string             `json:"given_name,omitempty"`
	FamilyName        string             `json:"family_name,omitempty"`
	Email             string             `json:"email,omitempty"`
	ClientID          string             `json:"clientId,omitempty"`
	ClientHost        string             `json:"clientHost,omitempty"`
	ClientIP          string             `json:"clientAddress,omitempty"`
	Authorization     Authorization      `json:"authorization,omitempty"`
}

type Authorization struct {
	Permissions []Permission `json:"permissions,omitempty"`
}

type Permission struct {
	Scopes []string `json:"scopes,omitempty"`
	Rsid   string   `json:"rsid,omitempty"`
	Rsname string   `json:"rsname,omitempty"`
}

type PermissionClaim struct {
	Id    string
	scope string
}

func (pc Permission) Contains(id string, scope string) bool {
	if pc.Rsid == id || pc.Rsname == id {
		if scope != "" {
			return Contains(pc.Scopes, scope)
		}
		return true
	}
	return false
}

func (c *Claims) HasPermission(resource string, scope string) bool {
	if c == nil || c.Authorization.Permissions == nil {
		return false
	}
	for _, permission := range c.Authorization.Permissions {
		if (permission.Rsid == resource || permission.Rsname == resource) && scope != "" {
			if permission.Scopes != nil && len(permission.Scopes) > 0 {
				if Contains(permission.Scopes, scope) {
					return true
				}
			}
		}
		return true
	}

	return false
}

// Contains tells whether a contains x.
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// APIError holds message and statusCode for api errors
type APICustomError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

// Error stringifies the APIError
func (apiError APICustomError) Error() string {
	return apiError.Message
}
