# CSCE 3550 Project 2 — SQLite JWKS Server

This Go HTTP server persists RSA private keys in `totally_not_my_privateKeys.db`, uses parameterized SQLite queries, signs RS256 JWTs, and exposes `POST /auth` and `GET /.well-known/jwks.json`.

## Run
```sh
go mod tidy
go run .
```

## Test and coverage
```sh
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Verify API
```sh
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth -H 'Content-Type: application/json' -d '{"username":"userABC","password":"password123"}'
curl -X POST 'http://localhost:8080/auth?expired=true'
```

Keys are persisted across restarts. The server generates a valid and expired key when missing. The database is intentionally excluded from source control because it contains private RSA keys.

Include genuine Gradebot and coverage screenshots before submission.
