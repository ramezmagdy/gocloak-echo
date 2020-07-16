package gocloakecho

import (
	"log"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v5"
	"github.com/Nerzal/gocloak/v5/pkg/jwx"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

// NewDirectGrantMiddleware instantiates a new AuthenticationMiddleWare when using the Keycloak Direct Grant aka
// Resource Owner Password Credentials Flow
//
// see https://www.keycloak.org/docs/latest/securing_apps/index.html#_resource_owner_password_credentials_flow and
// https://tools.ietf.org/html/rfc6749#section-4.3 for more information about this flow
//noinspection GoUnusedExportedFunction
func NewDirectGrantMiddleware(gocloak gocloak.GoCloak, realm string, clientID string, clientSecret *string, allowedScope *string, customHeaderName *string) AuthenticationMiddleWare {
	return &directGrantMiddleware{
		gocloak:          gocloak,
		realm:            realm,
		clientID:         clientID,
		clientSecret:     clientSecret,
		allowedScope:     allowedScope,
		customHeaderName: customHeaderName,
	}
}

type directGrantMiddleware struct {
	gocloak          gocloak.GoCloak
	realm            string
	clientID         string
	clientSecret     *string
	allowedScope     *string
	customHeaderName *string
}

// CheckTokenCustomHeader used to verify authorization tokens
func (auth *directGrantMiddleware) CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		realm := auth.realm

		if realm == "" {
			value, ok := c.Get(KeyRealm).(string)
			if ok {
				realm = value
			}
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		decodedToken, err := auth.stripBearerAndCheckToken(token, realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token: " + err.Error(),
			})
		}

		if !decodedToken.Valid {
			return c.JSON(http.StatusForbidden, gocloak.APIError{
				Code:    http.StatusForbidden,
				Message: "Invalid Token",
			})
		}

		return next(c)
	}
}

func (auth *directGrantMiddleware) stripBearerAndCheckToken(accessToken string, realm string) (*jwt.Token, error) {
	accessToken = extractBearerToken(accessToken)

	decodedToken, _, err := auth.gocloak.DecodeAccessToken(accessToken, realm)
	return decodedToken, err
}

func (auth *directGrantMiddleware) DecodeAndValidateToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		return next(c)
	}

}

// CheckToken used to verify authorization tokens
func (auth *directGrantMiddleware) CheckToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		token = extractBearerToken(token)

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Bearer Token missing",
			})
		}
		result, err := auth.gocloak.RetrospectToken(token, auth.clientID, *auth.clientSecret, auth.realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token:" + err.Error(),
			})
		}

		if !*result.Active {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or expired Token",
			})
		}

		return next(c)
	}
}

func extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func (auth *directGrantMiddleware) CheckScope(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		token = extractBearerToken(token)
		claims := &jwx.Claims{}
		_, err := auth.gocloak.DecodeAccessTokenCustomClaims(token, auth.realm, claims)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token",
			})
		}

		if !strings.Contains(claims.Scope, *auth.allowedScope) {
			return c.JSON(http.StatusForbidden, gocloak.APIError{
				Code:    http.StatusForbidden,
				Message: "Insufficient permissions to access the requested resource",
			})
		}

		return next(c)
	}
}

func (auth *directGrantMiddleware) Enforcer(requestConfig EnforcerConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			responseMode := ""
			token := ""

			if requestConfig.Permissions == nil || len(requestConfig.Permissions) <= 0 {
				return auth.accessDenied(c, "Access Denied")
			}

			if auth.customHeaderName != nil {
				token = c.Request().Header.Get(*auth.customHeaderName)
			}

			if token == "" {
				token = c.Request().Header.Get("Authorization")
			}

			if token == "" {
				return auth.accessDenied(c, "Authorization header missing")
			}

			token = extractBearerToken(token)

			if token == "" {
				return auth.accessDenied(c, "Bearer Token missing")
			}

			if requestConfig.ResponseMode == "" {
				responseMode = "permissions"
			} else {
				responseMode = requestConfig.ResponseMode
			}

			tokenClaim := &Claims{}
			decodedTokenClaim, err := auth.gocloak.DecodeAccessTokenCustomClaims(token, auth.realm, tokenClaim)
			if err != nil {
				return auth.accessDenied(c, "Bearer Token missing")
			}
			log.Println(decodedTokenClaim)

			requestOptions := gocloak.RequestingPartyTokenOptions{}
			requestOptions.Permissions = requestConfig.Permissions
			requestOptions.Audience = gocloak.StringP(requestConfig.Audience)

			grant, err := auth.gocloak.GetRequestingPartyToken(token, auth.realm, requestOptions)
			if err != nil {
				log.Println("Invalid or malformed token:" + err.Error())
				return auth.accessDenied(c, "Invalid or expired Token")
			}

			if grant == nil || grant.AccessToken == "" {
				log.Println("Invalid or malformed token null grant")
				return auth.accessDenied(c, "Invalid or expired Token")
			}

			permissionResult := auth.handlePermissions(requestConfig.Permissions, grant, responseMode)

			if permissionResult != true {
				return auth.accessDenied(c, "Invalid or expired Token")
			}

			user, _ := auth.gocloak.GetUserInfo(token, auth.realm)
			c.Set("user", user)

			return next(c)
		}
	}
}

func (auth *directGrantMiddleware) Protect() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := ""
			if auth.customHeaderName != nil {
				token = c.Request().Header.Get(*auth.customHeaderName)
			}

			if token == "" {
				token = c.Request().Header.Get("Authorization")
			}

			if token == "" {
				return c.JSON(http.StatusUnauthorized, gocloak.APIError{
					Code:    403,
					Message: "Authorization header missing",
				})
			}

			token = extractBearerToken(token)

			if token == "" {
				return c.JSON(http.StatusUnauthorized, gocloak.APIError{
					Code:    403,
					Message: "Bearer Token missing",
				})
			}
			decodedToken, _, err := auth.gocloak.DecodeAccessToken(token, auth.realm)
			if err != nil {
				log.Println("Invalid or malformed token:" + err.Error())
				return c.JSON(http.StatusUnauthorized, gocloak.APIError{
					Code:    403,
					Message: "Invalid or expired Token",
				})
			}

			if !decodedToken.Valid {
				return c.JSON(http.StatusUnauthorized, gocloak.APIError{
					Code:    403,
					Message: "Invalid or expired Token",
				})
			}
			user, _ := auth.gocloak.GetUserInfo(token, auth.realm)
			c.Set("user", user)

			return next(c)
		}
	}
}

func (auth *directGrantMiddleware) handlePermissions(requestPermissions []string, grant *gocloak.JWT, responseMode string) bool {
	var expectedPermissions []PermissionClaim

	claims := &Claims{}
	decodedClaim, err := auth.gocloak.DecodeAccessTokenCustomClaims(grant.AccessToken, auth.realm, claims)
	if err != nil {
		return false
	}
	log.Println(decodedClaim)

	for _, permission := range requestPermissions {
		s := strings.Split(permission, "#")
		p := PermissionClaim{
			s[0],
			"",
		}
		if len(s) > 1 {
			p.scope = s[1]
		}
		expectedPermissions = append(expectedPermissions, p)
	}
	log.Println(expectedPermissions)

	if responseMode == "permissions" || responseMode == "decision" {
		if claims.Authorization.Permissions == nil || len(claims.Authorization.Permissions) <= 0 {
			return false
		} else {
			for _, scope := range expectedPermissions {
				for _, permission := range claims.Authorization.Permissions {
					log.Println(permission)
					if permission.Contains(scope.Id, scope.scope) == false {
						return false
					}
				}
			}
		}
	} else {
		for _, scope := range expectedPermissions {
			if scope.Id != "" && scope.scope != "" {
				if claims.HasPermission(scope.Id, scope.scope) != true {
					return false
				}
			}
		}
	}
	return true
}

func (auth *directGrantMiddleware) accessDenied(c echo.Context, message string) error {
	return c.JSON(http.StatusUnauthorized, gocloak.APIError{
		Code:    403,
		Message: message,
	})
}
