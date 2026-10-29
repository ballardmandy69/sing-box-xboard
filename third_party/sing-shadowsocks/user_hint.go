package shadowsocks

import "context"

type userHintKey[U any] struct{}

// ContextWithUserHint selects one candidate identity; the protocol still authenticates its key.
// An unknown or incorrect hint fails authentication and does not fall back to the complete user list.
func ContextWithUserHint[U any](ctx context.Context, user U) context.Context {
	return context.WithValue(ctx, userHintKey[U]{}, user)
}

func UserHintFromContext[U any](ctx context.Context) (U, bool) {
	user, loaded := ctx.Value(userHintKey[U]{}).(U)
	return user, loaded
}
