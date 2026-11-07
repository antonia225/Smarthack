# Learning Mode attributions

NetCheck's Learning Mode uses a fixed allowlist in
[`knowledge/sources.json`](../knowledge/sources.json). Retrieved passages keep
their source URL, license, attribution, and retrieval time in their Markdown
front matter.

The allowlist includes MDN Web Docs (CC-BY-SA), IETF RFCs under the IETF Trust
legal provisions, OWASP IoT (CC-BY-SA 4.0), and U.S. government CISA/NIST
material. The CISA and NIST pages should be checked for their current page
terms each time the corpus is rebuilt.

Cloudflare, Professor Messer, and Bitdefender appear only as links in
`knowledge/resources.json`; their text is not copied.
