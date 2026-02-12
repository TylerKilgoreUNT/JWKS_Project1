# JWKS_Project1

This is the repository for Project 1: JWKS server for CSCE 3550: Spring 2026.

## Overview

This project implements a JWKS server with:

- RSA key generation with `kid` and expiry timestamps
- JWKS endpoint that serves only unexpired public keys
- `/auth` endpoint that returns a signed JWT, with an optional `expired` query parameter

## Endpoints

- `GET /.well-known/jwks.json`
  - Returns JWKS containing only unexpired public keys
- `POST /auth`
  - Returns a JSON body with a signed JWT
  - If `?expired` is present, the JWT is signed using the expired key and has an expired `exp`

## Running

The server listens on port 8080.

```bash
cargo run
```

## Tests

```bash
cargo test
```

## Linting and Formatting

```bash
cargo fmt
cargo clippy --all-targets --all-features
```
