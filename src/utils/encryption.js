const crypto = require('node:crypto');

function sha256(buffer) {
    const hash = crypto.createHash('sha256');
    hash.update(buffer);
    return hash.digest('hex');
}

function deriveKey(password, salt) {
    if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt);
    return crypto.scryptSync(String(password), salt, 32);
}

function encryptBuffer(plaintextBuffer, password) {
    if (!Buffer.isBuffer(plaintextBuffer)) {
        plaintextBuffer = Buffer.from(plaintextBuffer);
    }
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = deriveKey(password, salt);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    const tag = cipher.getAuthTag();

    const header = {
        v: 1,
        alg: 'aes-256-gcm',
        kdf: 'scrypt',
        hashAlg: 'sha256',
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        hash: sha256(plaintextBuffer),
        size: plaintextBuffer.length,
    };

    return {header, ciphertextB64: ciphertext.toString('base64')};
}

function decryptToBuffer(header, ciphertextB64, password) {
    const salt = Buffer.from(header.salt, 'base64');
    const iv = Buffer.from(header.iv, 'base64');
    const tag = Buffer.from(header.tag, 'base64');
    const key = deriveKey(password, salt);

    const ciphertext = Buffer.from(ciphertextB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const computedHash = sha256(plaintext);
    const verified = String(header.hash).toLowerCase() === computedHash.toLowerCase();
    return {plaintext, verified, computedHash};
}


function generateRsaKeyPairPEM(modulusLength = 2048) {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
        modulusLength,
        publicKeyEncoding: {type: 'spki', format: 'pem'},
        privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
    });
    return {publicKeyPem: publicKey, privateKeyPem: privateKey};
}

function rsaEncryptPublic(publicKeyPem, data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return crypto.publicEncrypt(
        {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        buf,
    );
}

function rsaDecryptPrivate(privateKeyPem, encData) {
    const buf = Buffer.isBuffer(encData) ? encData : Buffer.from(encData);
    return crypto.privateDecrypt(
        {
            key: privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        buf,
    );
}

function signRSAPSS(privateKeyPem, data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const signer = crypto.createSign('sha256');
    signer.update(buf);
    signer.end();
    const sig = signer.sign({key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32});
    return sig.toString('base64');
}

function verifyRSAPSS(publicKeyPem, data, signatureB64) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const sig = Buffer.from(signatureB64, 'base64');
    const verifier = crypto.createVerify('sha256');
    verifier.update(buf);
    verifier.end();
    return verifier.verify({key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32}, sig);
}

function encryptWithAesKey(plaintextBuffer, key32, iv12) {
    const key = Buffer.isBuffer(key32) ? key32 : Buffer.from(key32);
    const iv = iv12 ? (Buffer.isBuffer(iv12) ? iv12 : Buffer.from(iv12)) : crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {ciphertext, iv, tag};
}

function decryptWithAesKey(ciphertext, key32, iv12, tag) {
    const key = Buffer.isBuffer(key32) ? key32 : Buffer.from(key32);
    const iv = Buffer.isBuffer(iv12) ? iv12 : Buffer.from(iv12);
    const authTag = Buffer.isBuffer(tag) ? tag : Buffer.from(tag);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = {
    sha256,
    deriveKey,
    encryptBuffer,
    decryptToBuffer,
    generateRsaKeyPairPEM,
    rsaEncryptPublic,
    rsaDecryptPrivate,
    signRSAPSS,
    verifyRSAPSS,
    encryptWithAesKey,
    decryptWithAesKey,
};
