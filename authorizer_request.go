package rbac

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

type RequestInfo struct {
	Method     string
	Host       string
	RequestURI string
	Pattern    string
	RemoteAddr string
	Header     http.Header
	URL        *url.URL
	IsTLS      bool
}

func RequestAuthorizer(authorizer Authorizer, actions func(*http.Request) []string) func(*http.Request) Decision {
	if actions == nil {
		actions = defaultActions
	}

	pool := &sync.Pool{New: func() any {
		return new(Target)
	}}

	return func(r *http.Request) Decision {
		ctx := r.Context()
		claims := CtxClaims(ctx)
		assertions := CtxAssertions(ctx)

		target := pool.Get().(*Target)
		defer func() {
			target.reset()
			pool.Put(target)
		}()

		ctx = WithRequestInfo(ctx, RequestInfo{
			Method:     r.Method,
			Host:       r.Host,
			RequestURI: r.RequestURI,
			Pattern:    r.Pattern,
			RemoteAddr: r.RemoteAddr,
			Header:     r.Header,
			URL:        r.URL,
		})

		target.Assertions = assertions
		for _, action := range actions(r) {
			target.Action = action

			if authorizer.Authorize(ctx, claims, target) == DecisionAllow {
				return DecisionAllow
			}
		}

		return DecisionDeny
	}
}

func defaultActions(r *http.Request) []string {
	method, path := r.Method, r.URL.Path
	if path == "" {
		path = "/"
	}
	return []string{
		"*",
		method,
		path,
		fmt.Sprintf("%s %s", method, path),
	}
}
