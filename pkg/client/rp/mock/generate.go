package mock

//go:generate mockgen -package mock -destination ./verifier.mock.go github.com/xslasd/oidc/pkg/rp Verifier
