# AI Policy

> [!NOTE]
> By Tinyauth, we refer to the entire Tinyauth ([tinyauthapp](https://github.com/tinyauthapp)) organization and all the repositories under it.

At Tinyauth, we believe that LLMs (Large Language Models) can help speed up development given that they are used correctly. However, we are strictly against generated output with little to no human oversight.

## How we use LLMs in Tinyauth

### Code reviews

We use [CodeRabbit](https://www.coderabbit.ai/) for automated reviews that can help catch bugs early.

### In-line suggestions

In-line suggestions are a huge part of the development workflow because they essentially provide faster and more accurate IntelliSense.

### Sporadic LLM assisted development

We may use LLMs to help extend our testing suite or write initial code prototypes. However, we never merge code not fully understood by a human.

When we use an LLM to write any part of the code, we take full responsibility of the generated output. Thus, we are against the use of trailers like `co-developed` or `assisted-by` as an LLM cannot be held accountable for its generated code.

## How we expect the community to use LLMs

We expect the community to use LLMs in the same way we do, responsibly. We previously tried using more lax measures for LLM usage, but it seems like our instructions were ignored.

We don't have the bandwidth nor the time to triage and review slop pull requests/issues/security advisories/etc. If you didn't bother putting your time in a contribution, why should we put ours reviewing it?

That's why the following measures are in place.

### LLM disclosure is required

Every time an LLM is used, its usage should be disclosed. We provide relevant check boxes for disclosing the use of LLMs when creating an issue or a pull request.

As mentioned above, trailers like `co-developed` or `assisted-by` are **forbidden**. When you use an LLM for code generation, you **must** take full accountability of the code. We cannot hold accountable an LLM for broken code.

We will **not** accept any contributions pretending that they were written by a human while the code is clearly generated.

Security advisories should disclose their usage by checking the LLM usage checkbox.

### Human written descriptions are required

A human should write every part of the issue, pull request, security advisory or anything that interacts with our community.

We are all humans, we don't care about typos or grammar errors. We prefer English with honest mistakes rather than slop essays.

If you use an LLM for translation purposes, you **must** include the original description in the original language to follow the "written by a human" rule.

Every type of interaction that's not written by a human will be **ignored**.

### You are required to fully understand the output of the LLM

Reviewing takes time, when we review and comment on your pull request, issue or security advisory, we expect a human to be located behind the screen and be in a position to explain the code or the thought process behind every single line of code.

Don't copy and paste our comments to an LLM, we can do that ourselves.

### Only text is allowed

We cannot accept material such as pictures or audio because of multiple cases of them violating copyright infringement laws.

### Automated systems are not allowed

We are not a testing playground for agent harnesses such as OpenClaw or Hermes. If we notice any kind of unapproved automated system interacting with our repositories, it will be **immediately banned** with **no warning**.

Automated systems that the maintainers approve, such as CodeRabbit and the agents described in `AGENTS.md`, are exempt.

These are not suggestions, they are **rules** for interacting with the Tinyauth organization. If you violate them, your contribution will be **ignored**. Repeat offenders will be **banned**.