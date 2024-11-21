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
	URL        url.URL
	IsTLS      bool
}

func RequestAuthorizer(authorizer Authorizer, actions func(*http.Request) []string) func(*http.Request) error {
	if actions == nil {
		actions = defaultActions
	}

	pool := &sync.Pool{
		New: func() any {
			return new(Target)
		},
	}

	return func(r *http.Request) (err error) {
		var decision Decision = DecisionDeny
		defer func() {
			if decision == DecisionDeny && err == nil {
				err = ErrDeny
			}
		}()

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
			URL:        *r.URL,
		})

		if ctxTarget := CtxTarget(ctx); ctxTarget != nil {
			target.Action = ctxTarget.Action
			target.Metadata = ctxTarget.Metadata
			target.Assertions = make([]Assertion, len(assertions)+len(ctxTarget.Assertions))
			copy(target.Assertions, assertions)
			copy(target.Assertions[len(assertions):], ctxTarget.Assertions)

			decision, err = authorizer.Authorize(ctx, claims, target)
			return
		}

		target.Assertions = assertions
		for _, action := range actions(r) {
			target.Action = action

			if decision, err = authorizer.Authorize(ctx, claims, target); decision == DecisionAllow {
				return nil
			}
		}
		return
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
