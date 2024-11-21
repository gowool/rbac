package rbac

import "context"

type (
	claimsKey      struct{}
	targetKey      struct{}
	assertionsKey  struct{}
	requestInfoKey struct{}
)

func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

func CtxClaims(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey{}).(*Claims)
	return claims
}

func WithTarget(ctx context.Context, target *Target) context.Context {
	return context.WithValue(ctx, targetKey{}, target)
}

func CtxTarget(ctx context.Context) *Target {
	target, _ := ctx.Value(targetKey{}).(*Target)
	return target
}

func WithAssertions(ctx context.Context, assertions ...Assertion) context.Context {
	return context.WithValue(ctx, assertionsKey{}, assertions)
}

func CtxAssertions(ctx context.Context) []Assertion {
	assertions, _ := ctx.Value(assertionsKey{}).([]Assertion)
	return append(make([]Assertion, 0, len(assertions)), assertions...)
}

func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

func CtxRequestInfo(ctx context.Context) RequestInfo {
	info, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info
}
