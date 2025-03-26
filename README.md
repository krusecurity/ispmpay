# Isrdosec Payment

## Overview
Isrdosec Payment is a PCI DSS-compliant security package for handling payment security in Node.js applications. It provides encryption, authentication, rate limiting, logging, and other security features to protect sensitive payment data.

## Features
- **AES Encryption & Decryption**: Secure data encryption with customizable keys.
- **JWT Authentication**: Token-based authentication for secure API access.
- **JOSE Key Management**: Secure key generation and encryption.
- **Rate Limiting**: Prevents abuse and ensures API security.
- **Session Management**: Secure user sessions with Express Session.
- **Logging**: Advanced logging for monitoring security events.
- **Security Middleware**: Helmet, CORS, and compression for enhanced protection.
- **Health Check Endpoint**: Ensures server uptime monitoring.

## Installation
```sh
npm install ispmpay
```

## Environment Variables
Create a `.env` file in the root directory and configure the following variables:
```env
PORT=5000
NODE_ENV=development
JWT_SECRET=your_jwt_secret
SESSION_SECRET=your_session_secret
ALLOWED_ORIGINS=http://localhost:3000
```

## Usage
### Start the Server
```sh
npm start
```
### Development Mode (Auto-restart with Nodemon)
```sh
npm run dev
```

## API Endpoints
### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - User login

### Payment
- `POST /api/payments/process` - Process a secure payment
- `GET /api/payments/status/:id` - Retrieve payment status

### Health Check
- `GET /api/health` - Check system health and uptime

## Contributing
Contributions are welcome! Fork the repository and submit a pull request.

## License
MIT License. See `LICENSE` file for details.

## Maintainers
Developed and maintained by **ISRDO Security Team**.

