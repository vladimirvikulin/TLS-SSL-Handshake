const crypto = require('crypto');
const net = require('net');
const fs = require('fs');

const PORT = 5000;

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});
const serverRandom = crypto.randomBytes(16);

let sessionKey;

const server = net.createServer((socket) => {
    console.log('Client connected');

    socket.on('data', (data) => {
        const message = JSON.parse(data);

        if (message.type === 'hello') {
            console.log('Server: Received client hello:', message.clientRandom);

            socket.write(JSON.stringify({
                type: 'serverHello',
                serverRandom: serverRandom.toString('hex'),
                publicKey: publicKey.export({
                    type: 'pkcs1',
                    format: 'pem',
                }),
            }));
        } else if (message.type === 'premasterSecret') {
            console.log('Server: Received encrypted premaster secret');

            const premasterSecret = crypto.privateDecrypt(
                privateKey,
                Buffer.from(message.encryptedPremasterSecret, 'hex')
            );

            console.log('Server: Decrypted premaster secret:', premasterSecret.toString('hex'));

            sessionKey = crypto.createHash('sha256')
                .update(Buffer.concat([
                    Buffer.from(message.clientRandom, 'hex'),
                    serverRandom,
                    premasterSecret,
                ]))
                .digest();

            console.log('Server: Derived session key:', sessionKey.toString('hex'));

            socket.write(JSON.stringify({
                type: 'ready',
                serverRandom: serverRandom.toString('hex'),
                premasterSecret: premasterSecret.toString('hex'),
            }));
        } else if (message.type === 'secureMessage') {
            const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
            decipher.setAuthTag(Buffer.from(message.tag, 'hex'));
            const decryptedMessage = Buffer.concat([
                decipher.update(Buffer.from(message.encryptedMessage, 'hex')),
                decipher.final(),
            ]);

            console.log('Server: Received secure message:', decryptedMessage.toString());

            const responseCipher = crypto.createCipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
            const encryptedResponse = Buffer.concat([
                responseCipher.update('Hello, secure client!'),
                responseCipher.final(),
            ]);
            socket.write(JSON.stringify({
                type: 'secureMessage',
                encryptedMessage: encryptedResponse.toString('hex'),
                tag: responseCipher.getAuthTag().toString('hex'),
            }));
        } else if (message.type === 'secureFile') {
            const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
            decipher.setAuthTag(Buffer.from(message.tag, 'hex'));
            const decryptedFile = Buffer.concat([
                decipher.update(Buffer.from(message.encryptedFile, 'hex')),
                decipher.final(),
            ]);

            fs.writeFileSync('received_file.txt', decryptedFile);
            console.log('Server: Received and saved encrypted file as received_file.txt');
        }
    });

    socket.on('end', () => {
        console.log('Client disconnected');
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});