# Security Policy

## Supported Versions

It is recommended to use the [latest](https://github.com/tinyauthapp/tinyauth/releases/latest) available version of Tinyauth. This is because it includes security fixes, new features and dependency updates. Older versions, especially major ones, are not supported and won't receive security or patch updates.

## Security Scope and Trust Model

Tinyauth authenticates users and enforces configured access controls for reverse-proxy integrations and its OpenID Connect server. Its security boundaries include user identity, authentication state, sessions, credentials, authorization codes, tokens, and application access.

The assumptions below describe the intended deployment model. A report showing that an attacker can violate these boundaries while those assumptions hold is welcome.

### Reverse Proxies and Deployment

The reverse proxy is trusted to supply the original host, scheme, request URI, and client IP through the appropriate integration headers. Administrators must configure it to replace or remove conflicting client-supplied headers and prevent access to protected applications that bypasses authentication.

The `auth.trustedProxies` setting controls client-IP trust; it does not validate every header used by the proxy-auth integrations. Configure it before relying on IP access controls. A Unix socket must be accessible only to trusted proxy processes; a process with direct socket access is effectively a trusted proxy.

A request made directly to a proxy-auth endpoint with forged forwarding headers does not, by itself, demonstrate access to a protected application. Show that an external client can cause the proxy to authorize and forward that request. Security problems in our documented proxy configurations should still be reported privately, even when the correction belongs in the documentation.

### Identity Providers and Email Claims

Administrators are responsible for selecting OAuth/OIDC and LDAP providers that return trustworthy identities and attributes. Tinyauth trusts identity claims from configured providers and does not independently verify ownership of email addresses.

Upstream `email_verified` is not required by default because some providers do not expose it. Use the provider's `forceVerified` setting when verified email is required and supported. When issuing OIDC claims, Tinyauth intentionally sets `email_verified=true` for a nonempty email as an interoperability decision; this does not attest that Tinyauth performed email verification.

Accepting those claims under the default policy is expected behavior. Bypassing an explicitly enabled verification requirement, impersonating another identity through Tinyauth's own processing, or crossing a client or session boundary remains reportable.

### Access-Control Semantics

Path ACLs are regular expressions evaluated against the parsed and cleaned URL path. Actual query and fragment components are excluded; cleaning resolves dot segments and removes trailing slashes. Percent-encoded reserved characters remain path data rather than becoming query or fragment delimiters.

Rules are not automatically anchored. For example, `^/public$` matches only that path, while `^/admin(?:/|$)` matches a path and its descendants. Administrators must choose expressions that match the intended resources. Tinyauth does not emulate backend-specific handling of semicolons, trailing dots, or other valid path characters.

The `users.allow` and `users.block` options are alternative modes for local and LDAP users. Do not configure both; the block list takes precedence. OAuth users are governed by the separate `oauth.*` ACL options. Configure internationalized domains in their ASCII/Punycode form.

These semantics alone are not vulnerabilities. Incorrect parsing of a correctly supplied original request, or failure to enforce the applicable configured ACLs, remains reportable.

### Login Limits and Availability

Tinyauth uses bounded server-side caches for pending authentication flows and login attempts. Sufficient traffic can evict entries or prevent login completion. Username-based lockouts can be triggered by failed logins, and locked accounts intentionally receive distinguishable responses. Usernames are treated as opaque, case-sensitive identifiers; Tinyauth does not reproduce every LDAP server's matching rules.

These are accepted design trade-offs. Cache eviction under load, the documented lockout behavior, or differences from an LDAP server's username matching do not by themselves establish a vulnerability. Cache policy changes, additional normalization, and alternative rate-limiting strategies can be proposed as hardening improvements.

This is not a blanket exclusion of denial-of-service reports. Explain any distinct failure, such as unbounded resource consumption or a disproportionate availability impact beyond these behaviors, with measured request volume, duration, and recovery conditions.

## What Makes a Security Finding

Report a reproducible violation of authentication, authorization, identity isolation, or confidentiality within the trust model above. Examples include completing authentication while required TOTP verification is pending, accessing an application despite its applicable ACLs, or using another client's authorization code.

An intentional bypass configured by an administrator is expected behavior. Trust in a component or its configuration does not give every user or client authority over other identities, sessions, or applications.

For timing or other side-channel reports, provide evidence of an observable signal and explain how an attacker can use it under realistic conditions. A potentially unsafe operation identified by static analysis alone is insufficient to establish exploitability.

A report may lead to documentation, validation, hardening, or a regular bug fix without being classified as a Tinyauth vulnerability. Closure as a duplicate means the issue is tracked elsewhere; it does not mean the finding is invalid. If a previous decision does not cover your attack, explain the different root cause, reachable path, or security impact.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests as I won't be able to patch them in time and they may get exploited by malicious actors.

Instead, report them privately using [GitHub's Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) via the **Security** tab of this repository.

Or send us an email at <security@tinyauth.app>.

### A note on AI-assisted reports

If AI tooling (LLMs, automated scanners, agentic assistants, etc.) helped you discover, analyze, or write up this issue, please disclose that in your report. This is not a judgement, AI-assisted findings are welcome. Disclosing AI use up front helps maintainers understand how much additional verification may be necessary.

However, security reports generated entirely by AI with little or no human analysis or verification, such as directly copied LLM-generated descriptions, will be **closed**.

When submitting a report, please use the structure below so it can be triaged quickly.

---

### 1. Summary

A short, one-paragraph description of the vulnerability and its impact (e.g. what an attacker can achieve, who is affected, and under what conditions).

### 2. Steps to Reproduce / Proof of Concept

Provide a minimal, reliable reproduction:

1. Step one
2. Step two
3. Step three

Include any required input, payloads, configuration, or code snippets. Attach a PoC script or screenshots where helpful.

Include the following context:

- The Tinyauth version or commit and the relevant configuration, with secrets removed.
- The proxy/provider versions, integration type, and any relevant routing or header configuration.
- The attacker's access and exactly which inputs they control.
- Where applicable, a control request that is correctly denied and the attack request that succeeds. For proxy-auth bypasses, include the request through the proxy and the protected application's response.
- The violated boundary from this policy. If the behavior resembles a known issue, explain what is different.

### 3. Expected vs. Actual Behaviour

- **Expected:** what *should* happen
- **Actual:** what *does* happen, and why it's a security issue

### 4. Suggested Fix or Mitigation *(optional)*

If you have an idea for how to address the issue, describe it here. A private gist link is welcome but not required.

- **Have you tested this fix?** Yes / No
- **If yes,** briefly describe how it was tested and what was verified.

---

## What to Expect

- **Acknowledgement** within a reasonable timeframe after receiving your report
- **Updates** as the issue is investigated and addressed
- **Public credit** in the resulting advisory, along with any **CVE assigned**, unless you'd prefer to stay anonymous

We follow a **90-day coordinated disclosure** window: please allow up to 90 days from the date of your report for the issue to be investigated and patched before publicly disclosing it. The publication date - whether earlier if a fix lands sooner, or later if more time is genuinely needed - will be agreed with you in advance.
