# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@rvpn.org**

We will acknowledge receipt of your vulnerability report within 48 hours and will send a more detailed response within 72 hours indicating the next steps in handling your report.

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker achieve?
- **Reproduction**: Step-by-step instructions to reproduce
- **Environment**: Versions, platforms, configurations affected
- **Mitigation**: Any suggested fixes or workarounds
- **Your contact**: How to reach you for follow-up questions
- **Disclosure preference**: Your preferred timeline for public disclosure

### Encryption

If you need to encrypt your communication, you can use our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

[Replace with actual PGP key]

-----END PGP PUBLIC KEY BLOCK-----
```

Fingerprint: `[Replace with actual fingerprint]`

## Security Response Process

1. **Acknowledgment** (within 48 hours)
   - We confirm receipt of your report
   - Assign a tracking identifier

2. **Assessment** (within 72 hours)
   - Validate the vulnerability
   - Determine severity and impact
   - Identify affected versions

3. **Remediation** (timeline varies)
   - Develop and test a fix
   - Prepare security advisory
   - Coordinate release timing

4. **Disclosure**
   - Release patched version
   - Publish security advisory
   - Credit the reporter (unless anonymity requested)

## Disclosure Policy

We follow responsible disclosure practices:

- We ask that you give us reasonable time to address the issue before public disclosure
- We aim to address critical vulnerabilities within 30 days
- We will credit you in the advisory unless you prefer anonymity
- We will not take legal action against researchers who follow this policy

## Security Best Practices for Users

### Deployment

- Always use the latest version
- Enable automatic updates where possible
- Use systemd hardening (provided in examples)
- Run with minimal privileges
- Monitor logs for suspicious activity

### Key Management

- Protect your identity key file (identity.key)
- Store server prekey bundles securely
- Rotate keys periodically
- Never share private keys between clients

### Network Security

- Use TLS 1.3 for all connections
- Verify server certificates
- Enable firewall rules to restrict access
- Monitor for unusual connection patterns

## Known Security Considerations

### Current Limitations

1. **Single Server Trust**: Currently, R-VPN requires trusting a single relay server. Future versions will support decentralized relay discovery.

2. **No Quantum Resistance**: The current cryptographic primitives (X25519, ChaCha20-Poly1305) are not quantum-resistant. Post-quantum cryptography is on our roadmap.

3. **Traffic Analysis**: While content is encrypted, an observer can see timing and volume patterns. Padding is implemented but not yet configurable.

### Threat Model

R-VPN is designed to protect against:

- ✅ Passive network eavesdropping
- ✅ Active MITM attacks (with proper key verification)
- ✅ Compromised relay servers (cannot decrypt traffic)
- ✅ Forward secrecy attacks (keys rotate automatically)

R-VPN does NOT protect against:

- ❌ Endpoint compromise (your device or the target server)
- ❌ Traffic analysis by sophisticated adversaries
- ❌ Compromise of your identity private key
- ❌ Social engineering attacks

## Security Audit History

| Date | Auditor | Scope | Results |
|------|---------|-------|---------|
| TBD | TBD | TBD | TBD |

We are actively seeking independent security audits. If you are a security researcher or audit firm interested in reviewing R-VPN, please contact us at security@rvpn.org.

## Acknowledgments

We thank the following security researchers who have responsibly disclosed vulnerabilities:

- [Your name could be here]

## Contact

- **Security issues**: security@rvpn.org
- **General questions**: https://github.com/creativebastard/rvpn/discussions
- **Website**: https://rvpn.org

---

*This security policy is subject to change. Please refer to the latest version in the repository.*
