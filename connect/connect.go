package connect

import (
	"net/http"

	"github.com/view26/atlassian/connect/jwt"
)

// Lifecycle is the HTTP request payload of Connect Lifecycle webhooks
// Refer : https://developer.atlassian.com/cloud/jira/platform/app-descriptor/#lifecycle
type Lifecycle struct {
	Key            string `json:"key"`
	ClientKey      string `json:"clientKey"`
	ServerVersion  string `json:"serverVersion"`
	PluginsVersion string `json:"pluginsVersion"`
	BaseURL        string `json:"baseUrl"`
	ProductType    string `json:"productType"`
	Description    string `json:"description"`
	SEN            string `json:"serviceEntitlementNumber"`
	EventType      string `json:"eventType"`

	// Only available in installed webhook
	OauthClientID string `json:"oauthClientId"`
	SharedSecret  string `json:"sharedSecret"`

	// Deprecated - DON'T USE
	// PublicKey string `json:"-"`
}

// GetRequest returns an Atlassian Connect authentication compatible http.Request
func GetRequest(link, sharedSecret, addOnKey string) (req *http.Request, err error) {

	signingKey := []byte(sharedSecret)

	// Take context path as a fn argument if required.
	contextPath := ""

	jwt, err := jwt.Encode(link, contextPath, addOnKey, signingKey)
	if err != nil {
		return
	}

	// Take method as a fn argument if required.
	req, err = http.NewRequest("GET", link, nil)
	if err != nil {
		return
	}

	req.Header.Add("Authorization", "JWT "+jwt)
	return
}
