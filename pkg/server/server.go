package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"net/http"
	"net/url"

	"github.com/adrianliechti/loop/pkg/kubernetes"
	"github.com/adrianliechti/loop/pkg/system"
	"github.com/pkg/browser"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/console/pkg/auth"
	"github.com/openshift/console/pkg/auth/csrfverifier"
	"github.com/openshift/console/pkg/auth/sessions"
	"github.com/openshift/console/pkg/proxy"
	"github.com/openshift/console/pkg/server"
	"github.com/openshift/console/pkg/serverconfig"
	"github.com/openshift/console/pkg/version"
	oscrypto "github.com/openshift/library-go/pkg/crypto"
	"k8s.io/client-go/rest"
)

type Server struct {
	handler http.Handler
}

func New() (*Server, error) {
	k, err := kubernetes.New()

	if err != nil {
		return nil, err
	}

	srv := &server.Server{
		PublicDir:                    "./static",
		BaseURL:                      &url.URL{Path: "/"},
		Branding:                     "openshift",
		CustomProductName:            "",
		CustomLogoFile:               "",
		ControlPlaneTopology:         "",
		StatuspageID:                 "",
		DocumentationBaseURL:         &url.URL{},
		AlertManagerUserWorkloadHost: "",
		AlertManagerTenancyHost:      "",
		AlertManagerPublicURL:        &url.URL{},
		GrafanaPublicURL:             &url.URL{},
		PrometheusPublicURL:          &url.URL{},
		ThanosPublicURL:              &url.URL{},
		LoadTestFactor:               0,
		DevCatalogCategories:         "",
		DevCatalogTypes:              "",
		UserSettingsLocation:         "localstorage",
		EnabledConsolePlugins:        serverconfig.MultiKeyValue{},
		I18nNamespaces:               []string{},
		PluginProxy:                  "",
		ContentSecurityPolicy:        "",
		ContentSecurityPolicyEnabled: false,
		QuickStarts:                  "",
		AddPage:                      "",
		ProjectAccessClusterRoles:    "",
		Perspectives:                 "",
		Telemetry:                    serverconfig.MultiKeyValue{},
		ReleaseVersion:               version.Version,
		NodeArchitectures:            []string{},
		NodeOperatingSystems:         []string{},
		K8sMode:                      "disabled",
		CopiedCSVsDisabled:           false,
		Capabilities:                 []operatorv1.Capability{},
	}

	apiURL, _ := url.Parse(k.Config().Host)
	apiURL.Path = "/"

	srv.Authenticator = &authenticator{
		k: k,
	}

	srv.CSRFVerifier = csrfverifier.NewCSRFVerifier(srv.BaseURL, false)

	srv.ProxyHeaderDenyList = []string{"Cookie", "X-CSRFToken", "X-CSRF-Token"}

	srv.ServiceClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{
				InsecureSkipVerify: true,
			}),
		},
	}

	srv.InternalProxiedK8SClientConfig = k.Config()

	srv.K8sProxyConfig = &proxy.Config{
		Endpoint: apiURL,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		HeaderBlacklist: srv.ProxyHeaderDenyList,
	}

	srv.ClusterManagementProxyConfig = &proxy.Config{
		Endpoint: apiURL,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	srv.AnonymousInternalProxiedK8SRT, _ = rest.TransportFor(rest.AnonymousClientConfig(srv.InternalProxiedK8SClientConfig))

	srv.AuthMetrics = auth.NewMetrics(srv.AnonymousInternalProxiedK8SRT)

	consoleHandler, err := srv.HTTPHandler()

	if err != nil {
		return nil, err
	}

	return &Server{
		handler: consoleHandler,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) ListenAndServe() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := system.FreePort(9000)

	if err != nil {
		return err
	}

	addr := fmt.Sprintf("http://localhost:%d", port)

	go func() {
		time.Sleep(250 * time.Millisecond)

		if ctx.Err() != nil {
			return
		}

		println("Console available on " + addr)

		browser.OpenURL(addr)
	}()

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: s,
		// Disable HTTP/2, which breaks WebSockets.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    oscrypto.SecureTLSConfig(&tls.Config{}),
	}

	return server.ListenAndServe()
}

type authenticator struct {
	k kubernetes.Client
}

func (a *authenticator) Authenticate(w http.ResponseWriter, req *http.Request) (*auth.User, error) {
	t, err := a.k.Credentials()

	if err != nil {
		return nil, err
	}

	if t.Token == "" {
		return nil, errors.New("unable to get token")
	}

	return &auth.User{
		Token: t.Token,
	}, nil
}

func (a *authenticator) CallbackFunc(fn func(loginInfo sessions.LoginJSON, successURL string, w http.ResponseWriter)) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) }
}

func (a *authenticator) GetOCLoginCommand() string {
	return ""
}

func (a *authenticator) GetSpecialURLs() auth.SpecialAuthURLs {
	return auth.SpecialAuthURLs{}
}

func (a *authenticator) IsStatic() bool {
	return true
}

func (a *authenticator) LoginFunc(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (a *authenticator) LogoutFunc(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (a *authenticator) LogoutRedirectURL() string {
	return ""
}

func (a *authenticator) ReviewToken(r *http.Request) error {
	return nil
}
