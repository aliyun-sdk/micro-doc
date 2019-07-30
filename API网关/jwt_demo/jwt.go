package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"strconv"
	"time"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
)

type timeNonce struct{}

func (timeNonce) Nonce() (string, error) {
	return strconv.FormatInt(time.Now().Unix(), 36), nil
}

var (
	_ = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ZCasNZu7vmUs1HTv+9q
6BPvUU92+oOFOz0QhZDzD2PCY9oIIzG4esHXNKMFZHyd7Hb+tdDUUTIfFzHT7k+F
46tFEQ0HyTvPST9MPcQXWqIncDFaAHNyTkK2DFBw2pP/NoJhboDrMwJoPlAYGZVn
DpF8Zxx93GZym2Hx9v62kLyUOWmYNU3zMjvV6X7ysDdYOAqSeNQGXwWg5Y6jf/XZ
oMjqH6MsSZb4IJYroz9K0rBBjfvs5/4r3ENab3LawLlJyf01RRh1Eae139DNAhmq
B7dFNqUY4XbRWDU7+P9+oyOdAJ8NmC1464UL+66x7rUu6FsJXVPrDKnZ/8YJHwRE
iQIDAQAB
-----END PUBLIC KEY-----`

	rsaPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVkJqw1m7u+ZSz
UdO/72roE+9RT3b6g4U7PRCFkPMPY8Jj2ggjMbh6wdc0owVkfJ3sdv610NRRMh8X
MdPuT4Xjq0URDQfJO89JP0w9xBdaoidwMVoAc3JOQrYMUHDak/82gmFugOszAmg+
UBgZlWcOkXxnHH3cZnKbYfH2/raQvJQ5aZg1TfMyO9XpfvKwN1g4CpJ41AZfBaDl
jqN/9dmgyOofoyxJlvggliujP0rSsEGN++zn/ivcQ1pvctrAuUnJ/TVFGHURp7Xf
0M0CGaoHt0U2pRjhdtFYNTv4/36jI50Anw2YLXjrhQv7rrHutS7oWwldU+sMqdn/
xgkfBESJAgMBAAECggEACYxHfjR4DTMXVNUJtIENtIZ/opD87sJGiJl4TaBnXX7G
SBSNXJVye/qClpXbPdzcap//Tz2g4GhvP2g442SmxcD4e4SrnnGQGOQ9kl1b9e9d
+AQc0/xVVe5hmTdXdE49kMBPftNAsK0g3/hQu4QUcXBLsYhykBH8ebntSW+l1d6j
i7QrQCILMjNQTwfT4wFC0wHFre8B//WXZzEYPmSKikOsX4EH8QM0y1QziCqKydxc
W2JiO+poiABYnBzcnlSE0kZbo9ljiAYFkHHdXxI1L1UQcqYEU41iBTcNclnKQU84
yZ9el5Encs8TB/3dTAtcgWefU1LD3NRb+FZw9vgJAQKBgQD099RuxIUDPuZYBVa9
Y8FXaJPc8I5fzigPpJoHTWlHmQiH6EEumIyT9TjWDWEwYWV6Rcm8pZFUGe+JiPpu
FVvPfoRtqYCAuU6i54y/ClUfofles77ga7FYXpZGHxpAwjku9cXLCqPZ07OR7y3H
UjTvd2Rh8Hc85fPjQEaYs1U92QKBgQDfLrw4ne43ZkVe7nR9vqSsvDCTqF1r8S9n
Pyohkmo9NYQKkRQahUEaYXLAq+D9kxePNiH4fW6515HL96Q4qpEZ8Qat5v473eQ0
1FGGolrMUOztAH/o/TkwwOj+dztWa+IInfgrwRv33cHwQeWhk4gQMYUua3THWYq7
cuyKVZQeMQKBgQDRqvEi4YcrUQHcYq1sKl6ITtUH7MkfTRdS1EKVb3dltaDsmih4
Fk90MBY2d3sw6pvtfJ//nAJ4Zj50jE40PIm5XgNAzSxUgMbCfcckmFZlXcBPgy8j
bGl9Rm/+ko5o0RQaknd5oqC9RwpSJNIc4Mq4D4tWnHeiIvuNDS2fcxbJeQKBgEk2
sKI2FN5xm1IwEWDquGS9+4WE1tjBLxbEntKSkG1x79Xzj8+/ZQL9csKH3+/vX+wo
Cu7UXw1yDS8HFwVL1vvWmKVVwJLtEJ7QA8qR2g1qgr6gylUpNKissAJCJOIN1AGV
qMLZv44JXkStqWHe3uTJCfKXZ6C53AvwAG7E8ikRAoGAYhRbz5JIVHdczuLzeFRb
lFlPEzOb1ZmE10dSWJVuzkmSE5odh4k71sbfTHxligW1YYd3u68fKB/QeVFuGe3p
iwF/L1jWz8l95uHMPvQiwlcAzPKIg2d5b7jZMLXff2ET0hoVQu9ztSj95xm8vhmI
Yn0MR6szne8RnPsuwgSUGho=
-----END PRIVATE KEY-----`
)

var RSA *rsa.PrivateKey
var builder jwt.Builder

func init() {
	if block, _ := pem.Decode([]byte(rsaPrivateKey)); block == nil {
		log.Fatalln("failed to parse ras private key")
	} else if pk, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		log.Fatalf("failed to parse rsa private key, err = %v", err)
	} else {
		RSA = pk.(*rsa.PrivateKey)
		jwk := jose.JSONWebKey{
			Key:       RSA,
			Use:       "sig",
			Algorithm: string(jose.RS256),
		}
		// 将JSON结果配置到阿里云平台
		// json, err := jwk.MarshalJSON()
		jsk := jose.SigningKey{Key: jwk, Algorithm: jose.RS256}
		jso := jose.SignerOptions{EmbedJWK: true, NonceSource: timeNonce{}}
		if signer, err := jose.NewSigner(jsk, &jso); err != nil {
			log.Fatalf("failed to generate json web signer, err = %v", err)
		} else {
			builder = jwt.Signed(signer)
		}
	}
}

func GenerateJWT(data interface{}) (string, error) {
	return builder.Claims(data).CompactSerialize()
}
