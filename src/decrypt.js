const {argv} = require('node:process');
const fs = require('node:fs');
const path = require('node:path');
const {
    rsaDecryptPrivate,
    decryptWithAesKey,
    verifyRSAPSS,
    sha256,
} = require('./utils/encryption');

function printUsage() {
    console.log('Usage: node src/decrypt.js <EncryptedFileName.enc.json>');
    console.log('Encrypted file should be in src/outputs/');
    console.log('Example: node src/decrypt.js example.txt.enc.json');
}

(function main() {
    if (argv.length < 3) {
        printUsage();
        process.exit(1);
    }
    const encFileName = argv[2];
    const outputsDir = path.resolve(__dirname, 'outputs');
    const encPath = path.resolve(outputsDir, encFileName);
    const inputsDir = path.resolve(__dirname, 'inputs');
    const privPath = path.join(inputsDir, 'private_key.pem');
    const pubPath = path.join(inputsDir, 'public_key.pem');

    if (!fs.existsSync(encPath)) {
        console.error(`Encrypted file not found: ${encPath}`);
        process.exit(1);
    }
    if (!fs.existsSync(privPath) || !fs.existsSync(pubPath)) {
        console.error('Missing key pair in src/inputs (private_key.pem or public_key.pem). Run encrypt first to generate.');
        process.exit(1);
    }

    const envelope = JSON.parse(fs.readFileSync(encPath, 'utf8'));
    if (!envelope || !envelope.header || !envelope.ciphertext || !envelope.signature) {
        console.error('Invalid envelope. Expected { header, ciphertext, signature }');
        process.exit(1);
    }

    const privateKeyPem = fs.readFileSync(privPath, 'utf8');
    const publicKeyPem = fs.readFileSync(pubPath, 'utf8');

    try {
        const wrappedKey = Buffer.from(envelope.header.wrappedKey, 'base64');
        const aesKey = rsaDecryptPrivate(privateKeyPem, wrappedKey);

        const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
        const iv = Buffer.from(envelope.header.iv, 'base64');
        const tag = Buffer.from(envelope.header.tag, 'base64');

        const plaintext = decryptWithAesKey(ciphertext, aesKey, iv, tag);

        const verifiedSig = verifyRSAPSS(publicKeyPem, plaintext, envelope.signature);
        const computedHash = sha256(plaintext);
        const verifiedHash = computedHash.toLowerCase() === String(envelope.header.hash).toLowerCase();

        const baseName = encFileName.replace(/\.enc\.json$/i, '.txt');
        const outPath = path.join(outputsDir, baseName);
        fs.writeFileSync(outPath, plaintext);

        console.log(`Decrypted file written to: ${outPath}`);
        console.log(`Signature verification: ${verifiedSig ? 'OK' : 'FAILED'}`);
        console.log(`Hash in header: ${envelope.header.hash}`);
        console.log(`Hash computed: ${computedHash}`);
        console.log(`Hash verification: ${verifiedHash ? 'OK' : 'FAILED'}`);

        if (!verifiedSig || !verifiedHash) process.exitCode = 2;
    } catch (err) {
        console.error('Decryption failed:', err.message || err);
        process.exit(1);
    }
})();
