# Break-glass local administrator runbook

## Purpose and custody

Break-glass access is for a complete OIDC/IdP outage only. Exactly one canonical username is configured in the mounted server configuration. The only recoverable username/password pair belongs in the approved externally audited password vault. Elastic Maintainer, Kubernetes configuration, PVC state, logs, and operator workstations must not retain the plaintext password.

The application provides no password creation, reset, retrieval, or management API or CLI. Production operators perform this procedure with approved offline tooling and record the vault and Kubernetes changes through the normal audited change process.

## Pinned credential format

The mounted Secret key contains exactly:

```text
elastic-maintainer-break-glass/v1
generation <unpadded-base64url-of-16-to-64-random-bytes>
verifier $argon2id$v=19$m=65536,t=3,p=1$<unpadded-standard-base64-16-byte-salt>$<unpadded-standard-base64-32-byte-hash>
```

The verifier parameters, salt length, and hash length are pinned and cannot be relaxed through configuration.

## Initial provisioning or rotation

1. Open an audited change and obtain the canonical configured username.
2. In the approved password vault, generate a new high-entropy random password of at least 32 characters. Do not place it in a shell argument, command history, environment variable, ticket, chat, clipboard manager, or temporary file.
3. On an approved offline workstation, use an interactive, audited Argon2id tool that reads the password without echo. Configure Argon2id version 19, 65,536 KiB memory, three iterations, one lane, a fresh 16-byte cryptographic salt, and a 32-byte output. Export only the canonical PHC verifier shown above.
4. Generate a fresh opaque generation from at least 16 cryptographically random bytes and encode it as unpadded base64url. A generation is never reused, even if the password is unchanged.
5. Construct the three-line credential document exactly as specified. Store it in the dedicated Kubernetes Secret key referenced by `breakGlass.credentialSecret`. The break-glass Secret must be distinct from the session-key Secret. Apply it atomically through the authorized deployment workflow; never commit the document to source control.
6. Configure only the non-secret username and Secret reference:

   ```yaml
   breakGlass:
     enabled: true
     username: break-glass-admin
     credentialSecret:
       namespace: elastic-maintainer
       name: elastic-maintainer-break-glass
       key: credential-set
   ```

7. Verify that the projected credential document and shared session-key Secret are readable by the workload. Do not log or copy their contents during verification.
8. Block OIDC discovery, token, and JWKS access in a controlled test, then authenticate through **Emergency local access — IdP outage only**. Confirm the UI displays the red break-glass banner, administrator role, and 15-minute absolute expiry.
9. Confirm the application exposes no bearer credential and that the password does not appear in logs, audit events, browser storage, or PVC files.

## Mandatory action after every use

Immediately after emergency work, even if the session was brief or unsuccessful:

1. Sign out and record the emergency-access incident in the approved audit process.
2. Generate a new vault password, fresh salt, pinned Argon2id verifier, and fresh opaque generation using the procedure above.
3. Atomically replace the mounted credential document and update the audited vault entry. Never preserve the previous password as a vault history item if policy permits permanent removal.
4. Verify that the previous password is rejected.
5. Verify that every previously issued break-glass session is rejected immediately. A verifier, generation, username, enabled-state, credential Secret reference, or current session-key change must revoke it.
6. Verify the new credential once, then rotate again if policy treats verification as use.

## Emergency revocation

Disable `breakGlass.enabled` and remove the username/credential reference in the same atomic configuration update, or rotate the current session key. Either action invalidates existing emergency sessions. Restore access only through a new audited provisioning operation.
