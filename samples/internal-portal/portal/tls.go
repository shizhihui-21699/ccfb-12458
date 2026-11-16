package main
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
)

func tlsConfig() *tls.Config {
    priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = priv
    return &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // CBC 套件
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        },
    }
}
