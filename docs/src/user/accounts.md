# Account Management

ACME accounts are persistent identities that tie a public key to one or more email addresses. Every order, authorization, and certificate is associated with an account.

## Account lifecycle

```
                  ┌─────────┐
         create   │         │  deactivate
       ─────────► │  valid  │ ────────────►  deactivated
                  │         │
                  └─────────┘
```

Accounts start in `valid` status. A `valid` account can:

- Create new orders.
- Manage existing orders and authorizations.
- Download certificates.
- Revoke certificates it owns.
- Update its contact list.
- Rotate its key.
- Deactivate itself.

A `deactivated` account is permanently disabled. All subsequent requests using a deactivated account's key are rejected.

## Creating an account

Send a POST request to `/acme/new-account` with a JWS signed by the account's public key in `jwk` form. The payload must contain:

| Field | Type | Required | Description |
|---|---|---|---|
| `contact` | array of strings | No | mailto: URIs for contact addresses |
| `onlyReturnExisting` | boolean | No | If `true`, return the existing account or error |

Only `mailto:` URIs are accepted as contact values. Any other scheme causes a `unsupportedContact` error.

**Example payload:**

```json
{
  "contact": ["mailto:admin@example.com"],
  "onlyReturnExisting": false
}
```

**Response on creation (201 Created):**

```json
{
  "status": "valid",
  "contact": ["mailto:admin@example.com"],
  "orders": "https://acme.example.com/acme/orders/<account-id>"
}
```

The `Location` header contains the account URL: `https://acme.example.com/acme/account/<account-id>`.

If an account already exists for the submitted key and `onlyReturnExisting` is `false`, the server returns the existing account with HTTP 200 rather than creating a duplicate.

## Reading account details

POST to the account URL (`/acme/account/<id>`) with an empty payload (POST-as-GET). The `kid` header must reference the account being queried, and it must match the account ID in the URL.

## Updating contact information

POST to `/acme/account/<id>` with a payload containing the new `contact` array:

```json
{
  "contact": ["mailto:new-admin@example.com"]
}
```

Contact addresses are replaced entirely; partial updates are not supported.

## Deactivating an account

POST to `/acme/account/<id>` with:

```json
{
  "status": "deactivated"
}
```

The account is immediately marked `deactivated`. This action is irreversible.

## Key rollover

To replace an account's signing key without losing the account:

1. Construct an outer JWS signed with the **old key** addressed to `/acme/key-change`.
2. Embed an inner JWS signed with the **new key** as the payload. The inner JWS payload must contain `{ "account": "<account-url>" }`.

```
POST /acme/key-change
Content-Type: application/jose+json

{
  "protected": "<outer-header-signed-with-old-key>",
  "payload": "<inner-jws-signed-with-new-key>",
  "signature": "<outer-signature>"
}
```

The server verifies:
- The outer JWS is signed by the current account key.
- The inner JWS is signed by the new key (`jwk` must be present in the inner header).
- The inner payload's `account` field matches the account URL derived from the outer `kid`.
- The new key is not already registered to another account.

On success, the account's stored key and thumbprint are replaced with the new key. Subsequent requests must be signed with the new key.

## Security considerations

- Each account is identified by the SHA-256 thumbprint of its JWK public key. The thumbprint is stored in the database to enable fast lookup without storing or parsing the full public key on every request.
- Key rollover is the only mechanism to change the signing key. There is no password or other credential; possession of the private key is the sole proof of identity.
- Contact email addresses are stored as plain text JSON in the database and are not validated against any mail server.
