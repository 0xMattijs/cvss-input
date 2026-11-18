# Security policy

## Supported versions

Security fixes go into the latest release only. Update to the latest version of
`@alcyonsecurity/cvss-input` before you report a problem.

## Report a vulnerability

Don't open a public issue. Report the vulnerability privately through
[GitHub private vulnerability reporting](https://github.com/0xMattijs/cvss-input/security/advisories/new).

Include:

- The affected version.
- A description of the problem and its impact.
- Steps or a minimal input that reproduce it, such as a vector string or component props.

The maintainer will confirm the report, work on a fix, and publish a security advisory with the fixed
version. Please keep the details private until the advisory is published.

## Scope

The package parses untrusted vector strings and renders them in React. Examples of problems in scope:

- Input that makes parsing or scoring hang or use excessive memory, despite the `maxLength` limit.
- Input, layer labels, or vectors that the component renders as HTML or script instead of text.
- A vector that produces a wrong score in a way an attacker can exploit, such as a crafted vector that
  shows a lower severity than the official calculators give.

Scoring mistakes that aren't attacker-controlled are ordinary bugs. Report them as
[issues](https://github.com/0xMattijs/cvss-input/issues).
