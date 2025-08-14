# Netsight

Keycloak integration (quick start)

1. Start Keycloak (dev mode is fine) and create a realm (or use `master`).
2. Create a client:
   - Client type: OpenID Connect
   - Access type: public (for testing) or confidential
   - Valid redirect URIs: `http://localhost:3000/*`
   - Web origins: `*` (testing only)
   - Note the Client ID (used as audience)
3. Create a user and set a password.
4. Get an access token (resource owner password demo):
   - POST `{realm-url}/protocol/openid-connect/token`
   - body: `grant_type=password&client_id=<client_id>&username=<user>&password=<pwd>`
   - copy `access_token` from response
5. Run API with env:
```
KEYCLOAK_ISSUER=http://localhost:8080/realms/<realm>
KEYCLOAK_AUDIENCE=<client_id>
```
6. Call protected endpoints with header:
```
Authorization: Bearer <access_token>
```

