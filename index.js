const net = require('net');
const http = require('http');
const https = require('https');
const fs = require('fs');
const Greenlock = require('greenlock');
const store = require('greenlock-store-fs');
const {URL} = require('url');
const SocksClient = require('socks').SocksClient;


// Fetch environment variables
const DOMAIN_NAME = process.env.DOMAIN_NAME || 'example.com';
const CONFIG_FILE = process.env.CONFIG_FILE;

// Load profiles from config file or environment variables
let profiles = [];

function loadProfiles() {
    if (CONFIG_FILE && fs.existsSync(CONFIG_FILE)) {
        try {
            const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
            if (Array.isArray(config.profiles)) {
                profiles = config.profiles.map(profile => ({
                    ...profile,
                    WHITELIST_DOMAINS: profile.WHITELIST_DOMAINS || []
                }));
                console.log(`Loaded ${profiles.length} profiles from config file`);
            } else {
                throw new Error('Config file must contain a profiles array');
            }
        } catch (err) {
            console.error('Error loading config file:', err);
            process.exit(1);
        }
    } else {
        // Create single profile from environment variables (backwards compatibility)
        profiles = [{
            USERNAME: process.env.USERNAME || 'user',
            PASSWORD: process.env.PASSWORD || 'eQqIhv07Kgew',
            SOCKS_HOST: process.env.SOCKS_HOST || '',
            SOCKS_PORT: parseInt(process.env.SOCKS_PORT, 10),
            SOCKS_USERNAME: process.env.SOCKS_USERNAME || '',
            SOCKS_PASSWORD: process.env.SOCKS_PASSWORD || '',
            WHITELIST_DOMAINS: process.env.WHITELIST_DOMAINS
                ? process.env.WHITELIST_DOMAINS.split(',').map(d => d.trim().toLowerCase())
                : []
        }];
        console.log('Using single profile from environment variables');
    }
}

loadProfiles();

// Function to find matching profile for authentication
function findMatchingProfile(username, password) {
    return profiles.find(profile =>
        profile.USERNAME === username && profile.PASSWORD === password
    );
}

// Function to check if a domain is allowed for a specific profile
function isDomainAllowed(domain, profile) {
    if (!profile.WHITELIST_DOMAINS || profile.WHITELIST_DOMAINS.length === 0) {
        return true;
    }
    return profile.WHITELIST_DOMAINS.some(whitelistDomain => {
        whitelistDomain = whitelistDomain.toLowerCase();
        if (whitelistDomain.startsWith('*.')) {
            return domain.endsWith(whitelistDomain.slice(1)) ||
                domain === whitelistDomain.slice(2);
        }
        return domain === whitelistDomain;
    });
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

// Authentication function for CONNECT and regular HTTP requests
function authenticate(req) {
    const authHeader = req.headers['proxy-authorization'] || '';
    if (!authHeader) return null;
    const [authType, authValue] = authHeader.split(' ');
    if (authType !== 'Basic') return null;
    const [username, password] = Buffer.from(authValue, 'base64')
        .toString()
        .split(':');
    return findMatchingProfile(username, password);
}

// Handle CONNECT requests (HTTPS)
async function handleConnect(clientReq, clientSocket, head) {
    console.log('Received CONNECT request:', clientReq.url);

    // Check Basic Auth and get profile
    const profile = authenticate(clientReq);
    if (!profile) {
        console.log('Authentication failed');
        clientSocket.write(
            'HTTP/1.1 407 Proxy Authentication Required\r\n' +
            'Proxy-Authenticate: Basic realm="Proxy Authentication Required"\r\n' +
            'Connection: close\r\n\r\n'
        );
        clientSocket.end();
        return;
    }

    const [targetHost, targetPort] = clientReq.url.split(':');
    const port = parseInt(targetPort, 10) || 443;

    if (!isDomainAllowed(targetHost, profile)) {
        console.log(`Domain not allowed: ${targetHost}`);
        clientSocket.write(
            'HTTP/1.1 403 Forbidden\r\n' +
            'Connection: close\r\n\r\n'
        );
        clientSocket.end();
        return;
    }

    console.log(`\nCONNECT -> ${targetHost}:${port}`);

    if (!profile.SOCKS_HOST) {
        console.log('No SOCKS_HOST set; using direct net.connect');
        const targetSocket = net.connect(port, targetHost, () => {
            clientSocket.write(
                'HTTP/1.1 200 Connection Established\r\n' +
                'Proxy-Agent: Node.js-Proxy\r\n\r\n'
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

    if (!SocksClient) {
        console.error(
            'SOCKS_HOST is set, but the "socks" package is not installed. ' +
            'Please install it with: npm install socks'
        );
        clientSocket.end();
        return;
    }

    console.log(
        `Forwarding via SOCKS5 at ${profile.SOCKS_HOST}:${profile.SOCKS_PORT} -> ${targetHost}:${port}`
    );

    try {
        const {socket: socksSocket} = await SocksClient.createConnection({
            proxy: {
                host: profile.SOCKS_HOST,
                port: profile.SOCKS_PORT,
                type: 5,
                userId: profile.SOCKS_USERNAME || undefined,
                password: profile.SOCKS_PASSWORD || undefined
            },
            command: 'connect',
            destination: {
                host: targetHost,
                port: port
            }
        });

        clientSocket.write(
            'HTTP/1.1 200 Connection Established\r\n' +
            'Proxy-Agent: Node.js-Proxy\r\n\r\n'
        );
        if (head && head.length) {
            socksSocket.write(head);
        }

        socksSocket.pipe(clientSocket);
        clientSocket.pipe(socksSocket);

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

// Handle HTTP forwarding
async function handleRequest(clientReq, clientRes) {
    console.log(`Proxying HTTP request to: ${clientReq.url}`);

    // 1. Check Basic Auth
    const profile = authenticate(clientReq);
    if (!profile) {
        console.log('Authentication failed');
        clientRes.writeHead(407, {
            'Proxy-Authenticate': 'Basic realm="Proxy Authentication Required"',
            'Connection': 'close'
        });
        clientRes.end();
        return;
    }


    // 2. Parse the URL and check whitelist
    let url;
    try {
        url = new URL(clientReq.url);
    } catch (error) {
        console.error("Invalid URL:", clientReq.url, error);
        clientRes.writeHead(400, {'Connection': 'close'});
        clientRes.end('Invalid URL');
        return;
    }

    if (!isDomainAllowed(url.hostname, profile)) {
        console.log(`Domain not allowed: ${url.hostname}`);
        clientRes.writeHead(403, {'Connection': 'close'});
        clientRes.end('Forbidden');
        return;
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

    // 3. Direct or SOCKS5 forwarding
    if (!profile.SOCKS_HOST) {
        console.log('No SOCKS_HOST set; using direct http.request');
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
    } else {
        console.log(`Forwarding HTTP via SOCKS5 at ${profile.SOCKS_HOST}:${profile.SOCKS_PORT} -> ${url.hostname}:${url.port || 80}`);

        if (!SocksClient) {
            console.error(
                'SOCKS_HOST is set, but the "socks" package is not installed. ' +
                'Please install it with: npm install socks'
            );
            clientRes.writeHead(500, {'Connection': 'close'});
            clientRes.end('SOCKS proxy configured but "socks" package not installed.');
            return;
        }

        try {
            const destinationPort = parseInt(url.port, 10);
            const {socket: socksSocket} = await SocksClient.createConnection({
                proxy: {
                    host: profile.SOCKS_HOST,
                    port: profile.SOCKS_PORT,
                    type: 5,
                    userId: profile.SOCKS_USERNAME || undefined,
                    password: profile.SOCKS_PASSWORD || undefined
                },
                command: 'connect',
                destination: {
                    host: url.hostname,
                    port: destinationPort
                }
            });
            socksSocket.on('error', (err) => {
                console.error("SOCKS Error in HTTP", err);
                clientRes.writeHead(502, {'Connection': 'close'});
                clientRes.end('Error connecting to target via SOCKS5.');
            });


            // Send initial request line and headers to the SOCKS socket
            let initialRequest = `${clientReq.method} ${url.pathname + url.search} HTTP/1.1\r\n`;
            for (const key in options.headers) {
                initialRequest += `${key}: ${options.headers[key]}\r\n`;
            }
            initialRequest += '\r\n'; // End of headers
            socksSocket.write(initialRequest);


            // Pipe data both ways
            clientReq.pipe(socksSocket); // From Client, Through Proxy, to Target (via SOCKS)

            // Listen for the response from the SOCKS socket
            let responseHeaders = '';
            let statusCode = null;
            let headers = null;

            socksSocket.on('data', (chunk) => {
                responseHeaders += chunk.toString();
                const headerEndIndex = responseHeaders.indexOf('\r\n\r\n');

                if (statusCode === null && headerEndIndex !== -1) {
                    const statusLine = responseHeaders.substring(0, responseHeaders.indexOf('\r\n'));

                    const statusMatch = statusLine.match(/^HTTP\/1\.[01] (\d+) .*/);

                    if (!statusMatch) {
                        console.error("Invalid Status Line received", statusLine);
                        clientRes.writeHead(502, {'Connection': 'close'});
                        clientRes.end();
                        socksSocket.end();
                        return;
                    }

                    statusCode = parseInt(statusMatch[1], 10);
                    const rawHeaders = responseHeaders.substring(responseHeaders.indexOf('\r\n') + 2, headerEndIndex).split('\r\n');
                    headers = {};

                    for (const rawHeader of rawHeaders) {
                        const separatorIndex = rawHeader.indexOf(':');
                        if (separatorIndex === -1) continue;
                        const key = rawHeader.substring(0, separatorIndex).trim().toLowerCase();
                        const value = rawHeader.substring(separatorIndex + 1).trim();
                        headers[key] = value;
                    }
                    clientRes.writeHead(statusCode, headers);
                    const body = responseHeaders.substring(headerEndIndex + 4);
                    if (body)
                        clientRes.write(Buffer.from(body, 'binary')); // Write any initial body data
                    responseHeaders = '';

                } else if (statusCode !== null) {
                    clientRes.write(chunk); // Write body data
                }


            });

            socksSocket.on('end', () => clientRes.end());

        } catch (err) {
            console.error('Error connecting via SOCKS:', err);
            clientRes.writeHead(502, {'Connection': 'close'});
            clientRes.end('Error connecting to target via SOCKS5.');
        }
    }
}


// Create middleware handler for ACME challenges
const acmeMiddleware = greenlock.middleware();

// HTTP server (port 80) for handling Let's Encrypt challenges and HTTP proxy
const httpServer = http.createServer((req, res) => {
    // Serve ACME challenge or a simple 200 response
    if (req.url.startsWith('/.well-known/acme-challenge/')) {
        return acmeMiddleware(req, res);
    } else {
        if (req.method === 'CONNECT') {
            // Shouldn't happen as https server listens to connect, but in case.
            handleConnect(req, res);
        } else if (req.url.startsWith('http://')) {
            handleRequest(req, res);
        } else {
            res.writeHead(200);
            res.end('HTTP Server for ACME Challenge and Proxy');
        }

    }
});

// HTTPS server setup (port 443)
const httpsServer = https.createServer(greenlock.tlsOptions);

// Handle HTTPS CONNECT (we ignore plain HTTP here)
httpsServer.on('connect', handleConnect);

// Handle regular HTTP requests (Proxying)
httpsServer.on('request', (req, res) => {
    if (!req.url.startsWith('http://')) {
        res.writeHead(400, {'Connection': 'close'});
        res.end('Invalid request');
        return;
    }
    handleRequest(req, res);

});


// Error handling for servers
[httpServer, httpsServer].forEach((server) => {
    server.on('error', (err) => {
        console.error('Server error:', err);
    });
});

// Start servers
httpServer.listen(80, '0.0.0.0', () => {
    console.log(`HTTP server (ACME and Proxy) running on http://${DOMAIN_NAME}:80`);
});

httpsServer.listen(443, '0.0.0.0', () => {
    console.log(`HTTPS proxy server running on https://${DOMAIN_NAME}:443`);
});