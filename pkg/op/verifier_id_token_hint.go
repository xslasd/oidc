package op

import (
	"context"
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"time"

	"github.com/xslasd/oidc/pkg/oidc"
)

type IDTokenHintVerifier interface {
	oidc.Verifier
	SupportedSignAlgs() []string
	KeySet() oidc.KeySet
	ACR() oidc.ACRVerifier
	MaxAge() time.Duration
}

type idTokenHintVerifier struct {
	issuer            string
	maxAgeIAT         time.Duration
	offset            time.Duration
	supportedSignAlgs []string
	maxAge            time.Duration
	acr               oidc.ACRVerifier
	keySet            oidc.KeySet
}

func (i *idTokenHintVerifier) Issuer() string {
	return i.issuer
}

func (i *idTokenHintVerifier) MaxAgeIAT() time.Duration {
	return i.maxAgeIAT
}

func (i *idTokenHintVerifier) Offset() time.Duration {
	return i.offset
}

func (i *idTokenHintVerifier) SupportedSignAlgs() []string {
	return i.supportedSignAlgs
}

func (i *idTokenHintVerifier) KeySet() oidc.KeySet {
	return i.keySet
}

func (i *idTokenHintVerifier) ACR() oidc.ACRVerifier {
	return i.acr
}

func (i *idTokenHintVerifier) MaxAge() time.Duration {
	return i.maxAge
}

func NewIDTokenHintVerifier(issuer string, keySet oidc.KeySet) IDTokenHintVerifier {
	verifier := &idTokenHintVerifier{
		issuer: issuer,
		keySet: keySet,
	}
	return verifier
}

//VerifyIDTokenHint validates the id token according to
//https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDTokenHint(ctx context.Context, token string, v IDTokenHintVerifier) (oidc.IDTokenClaims, error) {
	claims := oidc.EmptyIDTokenClaims()
	decrypted, err :=jose.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	payload,err:=v.KeySet().VerifySignature(ctx,decrypted)
	if err!=nil{
		return nil, err
	}
	err = json.Unmarshal(payload, claims)
	if err!=nil{
		return nil, err
	}
	//payload, err := oidc.ParseToken(decrypted, claims)
	fmt.Println("payload",claims,err)
	if err != nil {
		return nil, err
	}

	if err := oidc.CheckIssuer(claims, v.Issuer()); err != nil {
		fmt.Println("CheckIssuer",err)
		return nil, err
	}

	//if err = oidc.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs(), v.KeySet()); err != nil {
	//	fmt.Println("CheckSignature",err)
	//	return nil, err
	//}

	if err = oidc.CheckExpiration(claims, v.Offset()); err != nil {
		fmt.Println("CheckExpiration",err)
		return nil, err
	}

	if err = oidc.CheckIssuedAt(claims, v.MaxAgeIAT(), v.Offset()); err != nil {
		fmt.Println("CheckIssuedAt",err)
		return nil, err
	}

	if err = oidc.CheckAuthorizationContextClassReference(claims, v.ACR()); err != nil {
		fmt.Println("CheckAuthorizationContextClassReference",err)
		return nil, err
	}

	if err = oidc.CheckAuthTime(claims, v.MaxAge()); err != nil {
		fmt.Println("CheckAuthTime",err)
		return nil, err
	}
	return claims, nil
}
