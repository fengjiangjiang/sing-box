//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	E "github.com/sagernet/sing/common/exceptions"
)

const accessJWTAssertionHeader = "Cf-Access-Jwt-Assertion"

var newAccessValidator = func(access AccessConfig) (accessValidator, error) {
	issuerURL := accessIssuerURL(access.TeamName, access.Environment)
	keySet := oidc.NewRemoteKeySet(context.Background(), issuerURL+"/cdn-cgi/access/certs")
	verifier := oidc.NewVerifier(issuerURL, keySet, &oidc.Config{
		SkipClientIDCheck: true,
	})
	return &oidcAccessValidator{
		verifier: verifier,
		audTags:  append([]string(nil), access.AudTag...),
	}, nil
}

type accessValidator interface {
	Validate(ctx context.Context, request *http.Request) error
}

type oidcAccessValidator struct {
	verifier *oidc.IDTokenVerifier
	audTags  []string
}

func (v *oidcAccessValidator) Validate(ctx context.Context, request *http.Request) error {
	accessJWT := request.Header.Get(accessJWTAssertionHeader)
	if accessJWT == "" {
		return E.New("missing access jwt assertion")
	}
	token, err := v.verifier.Verify(ctx, accessJWT)
	if err != nil {
		return err
	}
	if len(v.audTags) == 0 {
		return nil
	}
	for _, jwtAudTag := range token.Audience {
		for _, acceptedAudTag := range v.audTags {
			if acceptedAudTag == jwtAudTag {
				return nil
			}
		}
	}
	return E.New("access token audience does not match configured aud_tag")
}

func accessIssuerURL(teamName string, environment string) string {
	if strings.EqualFold(environment, "fed") || strings.EqualFold(environment, "fips") {
		return fmt.Sprintf("https://%s.fed.cloudflareaccess.com", teamName)
	}
	return fmt.Sprintf("https://%s.cloudflareaccess.com", teamName)
}

func validateAccessConfiguration(access AccessConfig) error {
	if !access.Required {
		return nil
	}
	if access.TeamName == "" && len(access.AudTag) > 0 {
		return E.New("access.team_name cannot be blank when access.aud_tag is present")
	}
	return nil
}

func accessValidatorKey(access AccessConfig) string {
	return access.TeamName + "|" + access.Environment + "|" + strings.Join(access.AudTag, ",")
}

type accessValidatorCache struct {
	access sync.RWMutex
	values map[string]accessValidator
}

func (c *accessValidatorCache) Get(accessConfig AccessConfig) (accessValidator, error) {
	key := accessValidatorKey(accessConfig)
	c.access.RLock()
	validator, loaded := c.values[key]
	c.access.RUnlock()
	if loaded {
		return validator, nil
	}

	validator, err := newAccessValidator(accessConfig)
	if err != nil {
		return nil, err
	}
	c.access.Lock()
	c.values[key] = validator
	c.access.Unlock()
	return validator, nil
}
