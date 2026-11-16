package main
import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/des"
    "math/rand"
    "encoding/hex"
)

// 写法 5：Go 的 md5.New
func legacyChecksum(data []byte) string {
    h := md5.New()
    h.Write(data)
    return hex.EncodeToString(h.Sum(nil))
}

func sha1Mac(data []byte) string {
    h := sha1.New()
    h.Write(data)
    return hex.EncodeToString(h.Sum(nil))
}

func desBlock(key []byte) (cipher.Block, error) {
    return des.NewCipher(key) // 单倍 DES
}

func sessionId() int {
    return rand.Intn(1000000) // math/rand 用于会话 ID
}
