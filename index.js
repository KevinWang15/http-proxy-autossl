const net = require('net');
const http = require('http');
const https = require('https');
const fs = require('fs');
const Greenlock = require('greenlock');
const store = require('greenlock-store-fs');

// Optional: Only needed if we have SOCKS_HOST set
let SocksClient;
try {
    SocksClient = require('socks').SocksClient;
} catch (err) {
    // If 'socks' isn't installed, we'll just skip it unless we need it.
    // But normally you'd run: npm install socks
}

// Fetch environment variables
const DOMAIN_NAME = process.env.DOMAIN_NAME || 'example.com';
const VALID_USERNAME = process.env.USERNAME || 'user';
const VALID_PASSWORD = process.env.PASSWORD || 'eQqIhv07Kgew';

// Optional SOCKS5 configuration
const SOCKS_HOST = process.env.SOCKS_HOST || '';
const SOCKS_PORT = parseInt(process.env.SOCKS_PORT, 10) || 1080;
const SOCKS_USERNAME = process.env.SOCKS_USERNAME || '';
const SOCKS_PASSWORD = process.env.SOCKS_PASSWORD || '';

// Whitelist configuration
const WHITELIST_DOMAINS = process.env.WHITELIST_DOMAINS
    ? process.env.WHITELIST_DOMAINS.split(',').map((d) => d.trim().toLowerCase())
    : [];

// Function to check if a domain is allowed
function isDomainAllowed(domain) {
    // If whitelist is empty, allow all domains
    if (WHITELIST_DOMAINS.length === 0) {
        return true;
    }
    // Otherwise, check if the requested domain is in the whitelist
    return WHITELIST_DOMAINS.includes(domain.toLowerCase());
}

// Greenlock store initialization
const greenlockStore = store.create({
    configDir: './greenlock'
});

// Greenlock configuration
const greenlock = Greenlock.create({
    server: 'https://acme-v02.api.letsencrypt.org/directory',
    email: 'contact@zoco.cc',
    agreeTos: true,
    configDir: './greenlock',
    communityMember: true,
    telemetry: true,
    approveDomains: [DOMAIN_NAME],
    store: greenlockStore
});

// Authentication function for CONNECT requests
function authenticateSocket(req) {
    const authHeader = req.headers['proxy-authorization'] || '';
    if (!authHeader) return false;
    const [authType, authValue] = authHeader.split(' ');
    if (authType !== 'Basic') return false;
    const [username, password] = Buffer.from(authValue, 'base64')
        .toString()
        .split(':');
    return username === VALID_USERNAME && password === VALID_PASSWORD;
}

// Handle CONNECT requests (HTTPS)
async function handleConnect(clientReq, clientSocket, head) {
    console.log('Received CONNECT request:', clientReq.url);
    console.log('Headers:', clientReq.headers);

    // 1. Check Basic Auth
    if (!authenticateSocket(clientReq)) {
        console.log('Authentication failed');
        clientSocket.write(
            'HTTP/1.1 407 Proxy Authentication Required\r\n' +
            'Proxy-Authenticate: Basic realm="Proxy Authentication Required"\r\n' +
            'Connection: close\r\n' +
            '\r\n'
        );
        clientSocket.end();
        return;
    }

    // 2. Parse the target from clientReq.url
    const [targetHost, targetPort] = clientReq.url.split(':');
    const port = parseInt(targetPort, 10) || 443;

    // 3. Whitelist check
    if (!isDomainAllowed(targetHost)) {
        console.log(`Domain not allowed: ${targetHost}`);
        clientSocket.write(
            'HTTP/1.1 403 Forbidden\r\n' +
            'Connection: close\r\n' +
            '\r\n'
        );
        clientSocket.end();
        return;
    }

    console.log(`\nCONNECT -> ${targetHost}:${port}`);

    // 4. If SOCKS_HOST is not set or empty, do a direct TCP connect
    if (!SOCKS_HOST) {
        console.log('No SOCKS_HOST set; using direct net.connect');
        const targetSocket = net.connect(port, targetHost, () => {
            clientSocket.write(
                'HTTP/1.1 200 Connection Established\r\n' +
                'Proxy-Agent: Node.js-Proxy\r\n' +
                '\r\n'
            );
            if (head && head.length) targetSocket.write(head);
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
        });

        targetSocket.on('error', (err) => {
            console.error('Target connection error:', err);
            clientSocket.end();
        });

        clientSocket.on('error', (err) => {
            console.error('Client connection error:', err);
            targetSocket.end();
        });

        targetSocket.on('end', () => clientSocket.end());
        clientSocket.on('end', () => targetSocket.end());
        return;
    }

    // 5. If SOCKS_HOST is set, forward via SOCKS5
    if (!SocksClient) {
        console.error(
            'SOCKS_HOST is set, but the "socks" package is not installed. ' +
            'Please install it with: npm install socks'
        );
        clientSocket.end();
        return;
    }

    console.log(
        `Forwarding via SOCKS5 at ${SOCKS_HOST}:${SOCKS_PORT} -> ${targetHost}:${port}`
    );

    try {
        const { socket: socksSocket } = await SocksClient.createConnection({
            proxy: {
                host: SOCKS_HOST,
                port: SOCKS_PORT,
                type: 5,
                userId: SOCKS_USERNAME || undefined,
                password: SOCKS_PASSWORD || undefined
            },
            command: 'connect',
            destination: {
                host: targetHost,
                port
            }
        });

        // Send 200 to client
        clientSocket.write(
            'HTTP/1.1 200 Connection Established\r\n' +
            'Proxy-Agent: Node.js-Proxy\r\n' +
            '\r\n'
        );
        // If there's leftover data from the client, write it to the socks socket
        if (head && head.length) {
            socksSocket.write(head);
        }

        // Pipe data both ways
        socksSocket.pipe(clientSocket);
        clientSocket.pipe(socksSocket);

        // Error & End events
        socksSocket.on('error', (err) => {
            console.error('SOCKS socket error:', err);
            clientSocket.end();
        });
        socksSocket.on('end', () => clientSocket.end());
        clientSocket.on('error', (err) => {
            console.error('Client socket error:', err);
            socksSocket.end();
        });
        clientSocket.on('end', () => socksSocket.end());

    } catch (err) {
        console.error('Error connecting via SOCKS:', err);
        clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        clientSocket.end();
    }
}

// Create middleware handler for ACME challenges
const acmeMiddleware = greenlock.middleware();

// HTTP server (port 80) for handling Let's Encrypt challenges
const httpServer = http.createServer((req, res) => {
    // Serve ACME challenge or a simple 200 response
    if (req.url.startsWith('/.well-known/acme-challenge/')) {
        return acmeMiddleware(req, res);
    } else {
        res.writeHead(200);
        res.end('HTTP Server for ACME Challenge');
    }
});

// HTTPS server setup (port 443)
const httpsServer = https.createServer(greenlock.tlsOptions);

// Only handle HTTPS CONNECT (we ignore plain HTTP here)
httpsServer.on('connect', handleConnect);

// Error handling for servers
[httpServer, httpsServer].forEach((server) => {
    server.on('error', (err) => {
        console.error('Server error:', err);
    });
});

// Start servers
httpServer.listen(80, '0.0.0.0', () => {
    console.log(`HTTP server (ACME) running on http://${DOMAIN_NAME}:80`);
});

httpsServer.listen(443, '0.0.0.0', () => {
    console.log(`HTTPS proxy server running on https://${DOMAIN_NAME}:443`);
});