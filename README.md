# HTTP Proxy Server with Auto SSL

A secure HTTP/HTTPS proxy server with automatic SSL certificate management using Let's Encrypt. This project provides a robust proxy server implementation with basic authentication and automatic SSL certificate renewal.

## Features

- HTTP and HTTPS proxy support
- Automatic SSL certificate management via Let's Encrypt
- Basic authentication for secure access
- Environment variable configuration
- Connection tunneling for HTTPS
- Proper error handling and logging

## Prerequisites

- Node.js (v12 or higher recommended)
- A registered domain name
- Port 80 and 443 available on your server
- Environment variables properly configured

## Installation

1. Clone the repository:
```bash
git clone http://github.com/KevinWang15/http-proxy-autossl
cd http-proxy-autossl
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
export DOMAIN_NAME=your-domain.com
export USERNAME=your-username
export PASSWORD=your-secure-password
```

## DNS Configuration

Before running the server, you need to set up your DNS records:

1. Log in to your domain registrar's DNS management panel
2. Create an A record:
    - Type: A
    - Host: @ (or subdomain if you're using one)
    - Value: Your server's public IP address
    - TTL: 3600 (or lower if you need faster propagation)

3. Wait for DNS propagation (can take up to 48 hours, but usually much faster)
4. Verify DNS setup using:
```bash
dig your-domain.com +short
```
The command should return your server's IP address.

## Configuration

The following environment variables are available for configuration:

- `DOMAIN_NAME`: Your domain name (default: 'example.com')
- `USERNAME`: Proxy authentication username (default: 'user')
- `PASSWORD`: Proxy authentication password (default: 'eQqIhv07Kgew')

**Important**: Always change the default credentials before deploying to production.

## Usage

To start the proxy server:

```bash
node index.js
```

The server will start and listen on:
- Port 80 for HTTP
- Port 443 for HTTPS

### Connecting to the Proxy

Configure your client to use the proxy with the following settings:

- Proxy Host: your-domain.com
- HTTP Proxy Port: 80
- HTTPS Proxy Port: 443
- Authentication: Basic
- Username: [configured username]
- Password: [configured password]

### Client Configuration Examples

#### Chrome with Extension
1. Install a proxy manager extension
2. Configure proxy settings:
    - Protocol: HTTPS
    - Server: your-domain.com
    - Port: 443
    - Username: [your username]
    - Password: [your password]

#### System-wide Proxy (Linux/macOS)
```bash
export http_proxy="http://username:password@your-domain.com:80"
export https_proxy="http://username:password@your-domain.com:443"
```

## Security Considerations

1. Always change the default credentials
2. Use strong passwords
3. Keep Node.js and dependencies updated
4. Monitor server logs for suspicious activity
5. Consider implementing rate limiting for production use

## SSL Certificates

SSL certificates are automatically managed using Let's Encrypt through the Greenlock package. Certificates will be automatically renewed when needed. Certificate files are stored in the `./greenlock` directory.

## Error Handling

The server implements comprehensive error handling for:
- Connection errors
- Authentication failures
- Invalid requests
- Server errors

Errors are logged to the console for monitoring and debugging.

## License

MIT

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## Support

For support, please open an issue in the repository's issue tracker.