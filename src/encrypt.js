const {argv} = require('node:process');
const fs = require('node:fs');
const path = require('node:path');
const {
    sha256,
    generateRsaKeyPairPEM,
    signRSAPSS,
    rsaEncryptPublic,
    encryptWithAesKey,
} = require('./utils/encryption');

function printUsage() {
    console.log('Usage: node src/encrypt.js <FileName>');
    console.log('File should be in src/inputs/');
    console.log('File should be in txt');
    console.log('Example: node src/encrypt.js example.txt');
}

function ensureKeyPair(inputsDir) {
    const privPath = path.join(inputsDir, 'private_key.pem');
    const pubPath = path.join(inputsDir, 'public_key.pem');
    if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
        return {
            privateKeyPem: fs.readFileSync(privPath, 'utf8'),
            publicKeyPem: fs.readFileSync(pubPath, 'utf8'),
        };
    }
    const {publicKeyPem, privateKeyPem} = generateRsaKeyPairPEM(2048);
    fs.writeFileSync(privPath, privateKeyPem);
    fs.writeFileSync(pubPath, publicKeyPem);
    console.log('Generated RSA key pair at src/inputs: private_key.pem, public_key.pem');
    return {publicKeyPem, privateKeyPem};
}

function extractFileNameWithoutExt(filePath) {
    return path.basename(filePath, path.extname(filePath));
}

(async () => {
    if (argv.length < 3) {
        printUsage();
        process.exit(1);
    }
    const inputFileName = argv[2];
    const inputsDir = path.resolve(__dirname, 'inputs');
    const inputPath = path.resolve(inputsDir, inputFileName);
    if (!fs.existsSync(inputPath)) {
        console.error(`Input file not found: ${inputPath}`);
        process.exit(1);
    }

    // Ensure RSA key pair exists in inputs/
    const {privateKeyPem, publicKeyPem} = ensureKeyPair(inputsDir);

    const plaintext = fs.readFileSync(inputPath);
    const hashHex = sha256(plaintext);
    const signatureB64 = signRSAPSS(privateKeyPem, plaintext);

    // Hybrid encryption: generate random AES key, encrypt data with AES-GCM, wrap AES key with RSA-OAEP
    const aesKey = fs.randomBytes ? fs.randomBytes(32) : require('node:crypto').randomBytes(32);
    const {ciphertext, iv, tag} = encryptWithAesKey(plaintext, aesKey);
    const wrappedKey = rsaEncryptPublic(publicKeyPem, aesKey);

    const envelope = {
        header: {
            v: 2,
            enc: 'hybrid: rsa-oaep(sha256) + aes-256-gcm',
            sig: 'rsa-pss(sha256)',
            hashAlg: 'sha256',
            hash: hashHex,
            size: plaintext.length,
            iv: iv.toString('base64'),
            tag: tag.toString('base64'),
            wrappedKey: wrappedKey.toString('base64'),
        },
        signature: signatureB64,
        ciphertext: ciphertext.toString('base64'),
    };

    const outputsDir = path.resolve(__dirname, 'outputs');
    fs.mkdirSync(outputsDir, {recursive: true});
    const outputFilename = extractFileNameWithoutExt(inputFileName);
    const outPath = path.join(outputsDir, `${outputFilename}.enc.json`);
    fs.writeFileSync(outPath, JSON.stringify(envelope, null, 2));

    console.log(`Encrypted+Signed file written to: ${outPath}`);
    console.log(`Hash (sha256): ${hashHex}`);
})();
