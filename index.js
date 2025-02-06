const net = require('net');
const http = require('http');
const https = require('https');
const fs = require('fs');
const Greenlock = require('greenlock');
const store = require('greenlock-store-fs');

// Fetch environment variables
const DOMAIN_NAME = process.env.DOMAIN_NAME || 'example.com';
const VALID_USERNAME = process.env.USERNAME || 'user';
const VALID_PASSWORD = process.env.PASSWORD || 'eQqIhv07Kgew';

// Whitelist configuration
const WHITELIST_DOMAINS = process.env.WHITELIST_DOMAINS
    ? process.env.WHITELIST_DOMAINS.split(',').map(d => d.trim().toLowerCase())
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
    configDir: './greenlock',
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
    store: greenlockStore,
});

// Authentication function for CONNECT requests
function authenticateSocket(req) {
    const authHeader = req.headers['proxy-authorization'] || '';
    if (!authHeader) return false;
    const [authType, authValue] = authHeader.split(' ');
    if (authType !== 'Basic') return false;
    const [username, password] = Buffer.from(authValue, 'base64').toString().split(':');
    return username === VALID_USERNAME && password === VALID_PASSWORD;
}

// Handle CONNECT tunnel
function handleConnect(clientReq, clientSocket, head) {
    console.log('Received headers:', clientReq.headers);

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

    console.log('Authentication successful');
    const [targetHost, targetPort] = clientReq.url.split(':');
    const port = parseInt(targetPort) || 443;

    // Whitelist check
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

    console.log(`Connecting to ${targetHost}:${port}`);
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

    targetSocket.on('end', () => {
        clientSocket.end();
    });

    clientSocket.on('end', () => {
        targetSocket.end();
    });
}

// Handle HTTP forwarding
function handleRequest(clientReq, clientRes) {
    console.log(`Proxying HTTP request to: ${clientReq.url}`);

    // Parse the URL to get the hostname
    let url;
    try {
        url = new URL(clientReq.url);
    } catch (error) {
        console.error('Invalid URL:', clientReq.url);
        clientRes.writeHead(400, {'Connection': 'close'});
        return clientRes.end('Invalid request URL');
    }

    // Whitelist check
    if (!isDomainAllowed(url.hostname)) {
        console.log(`Domain not allowed: ${url.hostname}`);
        clientRes.writeHead(403, {'Connection': 'close'});
        return clientRes.end('Forbidden: Domain not in whitelist');
    }

    const options = {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: clientReq.method,
        headers: {
            ...clientReq.headers,
            host: url.host
        }
    };

    // Remove proxy-specific headers
    delete options.headers['proxy-connection'];
    delete options.headers['proxy-authorization'];

    const proxyReq = http.request(options, (proxyRes) => {
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(clientRes);
    });

    proxyReq.on('error', (err) => {
        console.error('Proxy request error:', err);
        clientRes.writeHead(500, {'Connection': 'close'});
        clientRes.end('Proxy request failed');
    });

    clientReq.pipe(proxyReq);
}

// Create middleware handler for ACME challenges
const acmeMiddleware = greenlock.middleware();

// HTTP server for handling Let's Encrypt challenges
const httpServer = http.createServer((req, res) => {
    if (req.url.startsWith('/.well-known/acme-challenge/')) {
        return acmeMiddleware(req, res);
    } else {
        res.writeHead(200);
        res.end('HTTP Proxy Server');
    }
});

// HTTPS server setup
const httpsServer = https.createServer(greenlock.tlsOptions);

// Handle CONNECT requests (for HTTPS)
httpsServer.on('connect', handleConnect);

// Handle regular HTTP requests
httpsServer.on('request', (req, res) => {
    if (!req.url.startsWith('http://')) {
        res.writeHead(400, {'Connection': 'close'});
        res.end('Invalid request');
        return;
    }
    handleRequest(req, res);
});

// Error handling for servers
[httpServer, httpsServer].forEach(server => {
    server.on('error', (err) => {
        console.error('Server error:', err);
    });
});

// Start servers
httpServer.listen(80, '0.0.0.0', () => {
    console.log(`HTTP server running on http://${DOMAIN_NAME}:80`);
});

httpsServer.listen(443, '0.0.0.0', () => {
    console.log(`HTTPS proxy server running on https://${DOMAIN_NAME}:443`);
});