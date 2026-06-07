# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Secure Push seriously. If you discover a security vulnerability, please follow these steps:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email us directly at **security@secure-push.dev** with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact of the vulnerability
   - Any suggested fixes (if available)

## What to Expect

- We will acknowledge receipt of your vulnerability report within 3 business days.
- We will provide a more detailed response within 7 business days indicating the next steps.
- We will work with you to understand and resolve the issue.
- We will keep you informed of the progress towards a fix.
- After the issue is resolved, we will publicly acknowledge your responsible disclosure (unless you prefer to remain anonymous).

## Security Best Practices for Users

- Always keep Secure Push updated to the latest version.
- Review and customize the default detector rules for your project.
- Use `.secure-push.yaml` to configure ignore rules for false positives.
- Never commit `.env` files or secrets to your repository.
- Run Secure Push in CI/CD pipelines for continuous protection.

Thank you for helping keep Secure Push and our community safe!
