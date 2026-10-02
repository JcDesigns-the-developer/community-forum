# Community Forum

A simple full-stack forum designed to be self-hosted behind Tor. GitHub stores the application source; runtime users, sessions, and posts stay in the server SQLite database.

## Features
- Registration and login
- bcrypt password hashing
- SQLite persistence
- Forums, threads, replies and search
- User profiles
- Admin moderation tools
- Reports and bans
- Rate limiting and security headers
- No CDN dependencies
- Tor hidden-service example

## Run
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Change `ADMIN_PASSWORD`.
4. Run `npm install`.
5. Run `npm start`.
6. Open http://127.0.0.1:3000

The configured admin account is created automatically on startup if it does not exist.

## Tor
Keep the app on 127.0.0.1 and let Tor expose it. See `tor/torrc.example`.
Never commit the SQLite database, session material, onion keys, or other secrets.
