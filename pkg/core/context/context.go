package contextx

import (
	"context"

	"github.com/ibm-verify/verify-sdk-go/x/logx"
)

type ContextKey string

const (
	// VerifyCtxKey is the context key holding verify specific context
	VerifyCtxKey ContextKey = "VCTX"
)

type VerifyContext struct {
	Logger *logx.Logger

	Tenant string

	Token string
}

func NewContextWithVerifyContext(parentContext context.Context, logger *logx.Logger) (context.Context, error) {
	vc := &VerifyContext{
		Logger: logger,
	}

	ctx := context.WithValue(parentContext, VerifyCtxKey, vc)
	return ctx, nil
}

func GetVerifyContext(ctx context.Context) *VerifyContext {
	vc, _ := ctx.Value(VerifyCtxKey).(*VerifyContext)
	return vc
}
