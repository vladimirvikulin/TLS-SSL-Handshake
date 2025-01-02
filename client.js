const crypto = require('crypto');
const net = require('net');

const PORT = 5000;
const clientRandom = crypto.randomBytes(16);

const client = net.createConnection({ port: PORT }, () => {
    console.log('Connected to server');

    console.log('Client: Sending hello');
    client.write(JSON.stringify({
        type: 'hello',
        clientRandom: clientRandom.toString('hex'),
    }));
});

let sessionKey;
client.on('data', (data) => {
    const message = JSON.parse(data);

    if (message.type === 'serverHello') {
        console.log('Client: Received server hello:', message.serverRandom);
        console.log('Client: Received server public key');

        const serverPublicKey = crypto.createPublicKey({
            key: message.publicKey,
            type: 'pkcs1',
            format: 'pem',
        });

        const premasterSecret = crypto.randomBytes(16);
        console.log('Client: Generated premaster secret:', premasterSecret.toString('hex'));

        const encryptedPremasterSecret = crypto.publicEncrypt(
            serverPublicKey,
            premasterSecret
        );

        console.log('Client: Sending encrypted premaster secret');
        client.write(JSON.stringify({
            type: 'premasterSecret',
            encryptedPremasterSecret: encryptedPremasterSecret.toString('hex'),
            clientRandom: clientRandom.toString('hex'),
        }));
    } else if (message.type === 'ready') {
        console.log('Client: Received ready message from server');

        sessionKey = crypto.createHash('sha256')
            .update(Buffer.concat([
                Buffer.from(clientRandom, 'hex'),
                Buffer.from(message.serverRandom, 'hex'),
                Buffer.from(message.premasterSecret, 'hex'),
            ]))
            .digest();

        console.log('Client: Derived session key:', sessionKey.toString('hex'));
        console.log('Client: Secure channel established!');

        sendSecureMessage('Hello, secure server!');
        sendFile('example.txt');
    } else if (message.type === 'secureMessage') {
        const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
        decipher.setAuthTag(Buffer.from(message.tag, 'hex'));
        const decryptedMessage = Buffer.concat([decipher.update(Buffer.from(message.encryptedMessage, 'hex')), decipher.final()]);
        console.log('Client: Received message from server:', decryptedMessage.toString());
    }
});

client.on('end', () => {
    console.log('Disconnected from server');
});

function sendSecureMessage(message) {
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
    const encryptedMessage = Buffer.concat([cipher.update(message), cipher.final()]);
    console.log('Client: Sending encrypted message');
    client.write(JSON.stringify({
        type: 'secureMessage',
        encryptedMessage: encryptedMessage.toString('hex'),
        tag: cipher.getAuthTag().toString('hex'),
    }));
}

function sendFile(filename) {
    const fs = require('fs');
    const fileContent = fs.readFileSync(filename);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
    const encryptedFile = Buffer.concat([cipher.update(fileContent), cipher.final()]);
    console.log('Client: Sending encrypted file');
    client.write(JSON.stringify({
        type: 'secureFile',
        encryptedFile: encryptedFile.toString('hex'),
        tag: cipher.getAuthTag().toString('hex'),
    }));
}