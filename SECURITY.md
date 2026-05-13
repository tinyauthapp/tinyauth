# Security Policy

## Supported Versions

It is recommended to use the [latest](https://github.com/tinyauthapp/tinyauth/releases/latest) available version of Tinyauth. This is because it includes security fixes, new features and dependency updates. Older versions, especially major ones, are not supported and won't receive security or patch updates.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests as I won't be able to patch them in time and they may get exploited by malicious actors.

Instead, report them privately using [GitHub's Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) via the **Security** tab of this repository.

Or send us an email at <security@tinyauth.app>.

### A note on AI-assisted reports

If AI tooling (LLMs, automated scanners, agentic assistants, etc.) helped you discover, analyse, or write up this issue, please say so in your report. This isn't a judgement - AI-assisted findings are welcome - but disclosing it up front helps maintainers calibrate how much additional verification a report needs, and tends to make the report itself clearer.

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
