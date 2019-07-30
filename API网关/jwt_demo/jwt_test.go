package utils

import (
	"reflect"
	"testing"
	"time"

	"github.com/square/go-jose/v3/jwt"
)

func TestGenerateJWT(t *testing.T) {
	claims := jwt.Claims{
		Issuer:    "",
		Subject:   "",
		Audience:  nil,
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute)),
		NotBefore: nil,
		IssuedAt:  nil,
		ID:        "1",
	}
	if token, err := GenerateJWT(claims); err != nil {
		t.Errorf("generate jwt failed, err = %v", err)
	} else if v, err := jwt.ParseSigned(token); err != nil {
		t.Errorf("parse jwt failed, err = %v", err)
	} else {
		var newClaims jwt.Claims
		if err = v.Claims(&RSA.PublicKey, &newClaims); err != nil {
			t.Errorf("get claims failed, err = %v", err)
		} else if reflect.DeepEqual(claims, newClaims) == false {
			t.Error("unexpected result, expect = equal, but = not equal")
		} else {
			exp1 := (jwt.Expected{}).WithTime(time.Now())
			if err = claims.Validate(exp1); err != nil {
				t.Errorf("unexpected result, expect = no error, but = %v", err)
			}
			exp2 := (jwt.Expected{}).WithTime(time.Now().Add(2 * time.Minute))
			if err = claims.Validate(exp2); err == nil {
				t.Error("unexpected result, expect = has error, but = no error")
			}
		}
	}
}
