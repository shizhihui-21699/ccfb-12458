const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// 写法 6：Node.js createHash md5
function checksum(buf) {
    return crypto.createHash("md5").update(buf).digest("hex");
}
// 写法 7：createCipheriv + DES-EDE3-CBC（OpenSSL 命名）
function encrypt3des(key, iv, data) {
    const c = crypto.createCipheriv("des-ede3-cbc", key, iv);
    return Buffer.concat([c.update(data), c.final()]);
}
function forgeToken(payload, key) {
    return jwt.sign(payload, key, { algorithm: "none" }); // alg=none
}
function randomish() { return Math.random().toString(36); }
module.exports = { checksum, encrypt3des, forgeToken, randomish };
