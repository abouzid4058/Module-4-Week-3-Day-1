# expapp-owasp

An Express.js authentication app with OWASP Top 10 security implementations.

## Features

- User registration & login (MongoDB + Passport.js)
- Password hashing with salt (passport-local-mongoose)
- EJS templating engine

## OWASP Security Implementations

| OWASP Risk | Protection | Package |
|---|---|---|
| Injection Attacks | NoSQL data sanitization | `express-mongo-sanitize` |
| Broken Authentication | Rate limiting (brute force/DOS) | `express-rate-limit` |
| Broken Authentication | Body payload limit (DOS) | `express` built-in |
| XSS Attacks | Input sanitization | `xss-clean` |
| XSS / Security Misconfiguration | Secure HTTP headers | `helmet` |
| Broken Authentication | Secure session cookie (httpOnly, secure, maxAge) | `express-session` |

## Extra: Form Validation

Server-side validation on the Register form:
- Username: minimum 4 characters, alphanumeric + underscore only
- Password: min 8 chars, must include uppercase, number, and special character
- Error messages displayed inline near input fields

## Setup

```bash
npm install
nodemon app.js
```

Visit `http://localhost:3000`

> **Note:** Requires a running MongoDB instance on `mongodb://localhost/auth_demo`
