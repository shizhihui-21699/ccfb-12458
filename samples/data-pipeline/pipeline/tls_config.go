package main
import "crypto/tls"

func modernTLS() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        // TLS 1.3 混合后量子组（试点）
        CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
    }
}
