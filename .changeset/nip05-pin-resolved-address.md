---
'nostream': patch
---

fix(nip05): refuse a verification host that resolves to a private address

NIP-05 verification fetched the domain from an author's kind-0 profile but only checked the text of a redirect URL, so a domain whose DNS points at loopback, a private network or a cloud metadata address was still fetched, on the first request and on its redirect. Each host is now resolved and refused before connecting when any of its addresses is on the private-address blocklist the NIP-11 probe already used (now shared, with `fec0::/10` added), a redirect to an IPv4 literal is checked against the same list, and the request ignores `HTTPS_PROXY` and `NODE_USE_ENV_PROXY`, because a proxy would resolve the name itself and skip the check. A deliberate limit: a relay that reaches the internet only through a proxy can no longer verify NIP-05 identifiers.
