# DomainJackr

Passive domain-takeover hunting for Burp Suite.
**DomainJackr** scans response bodies/headers, extracts registrable domains (eTLD+1) from realistic contexts (URLs, headers, CSP, CSS `url()`, emails), and checks RDAP to see whether they’re **unregistered/claimable**. New, claimable domains are raised as **Scanner issues** with evidence.

---


## Installing in Burp

1. Build your JAR, or pull it from the releases github tab.
2. In Burp: **Extensions → Installed → Add → Select file...**
3. Ensure the extension loads without errors. You should see “**DomainJackr**” as the name.

---

## Features

* **Context-aware extraction** (low noise)

    * URLs: `http(s)://`, `ws(s)://`, `ftp://`
    * Scheme-relative: `//host/path`
    * Emails: `user@host.tld`
    * Headers: `Host`, `Origin`, `Referer`, `Content-Location`
    * CSP directives (`default-src`, `script-src`, …)
    * CSS `url(...)`
* **Public Suffix List (PSL)** reduction → returns **registrable domains (eTLD+1)** only.
* **RDAP-compliant** checks (via Burp’s HTTP stack)

    * Sends `Accept: application/rdap+json`
    * Follows redirects
    * Treats HTTP **404** or RDAP **Problem Document** with `errorCode: 404` as **claimable**
    * Treats domain objects (`objectClassName: "domain"`) as **registered**
    * Handles 429 rate limits conservatively
* **Project-scoped dedupe**: domains are persisted in the Burp **project file** (logged/flagged once).
* **Noise controls**

    * Skip non-text responses (allow-list: `text/*`, JSON, XML, HTML, JS, etc.)
    * Skip known platform/CDN registrable domains (e.g., `amazonaws.com`, `appspot.com`, `cloudfront.net`, …).
* **Scanner integration**: results show up as Burp **Issues** with the originating request/response attached.

---

## Q\&A

**Q: I know a domain is claimable, but the tool didn’t flag it. Why?**
**A:** Some TLDs do **not** expose a designated RDAP server in IANA’s bootstrap, so there’s no reliable RDAP query to make. In those cases, the tool won’t be able to determine claimability. Examples include **`.me`**, **`.gg`**, **`.be`**, and **`.io`**.
If you’re certain the domain is unregistered, you can still verify via registrar/WHOIS, but RDAP-based detection won’t work without an RDAP endpoint.

**Q: It flagged a domain under a big provider (e.g., `s3.amazonaws.com`). Is that actionable?**
**A:** Usually no. Those are shared provider domains and not directly registrable by you. We skip many of these by default via the **skip list**. Add more as needed.

**Q: Can I scan binary files like PDFs or Office docs?**
**A:** By default, no (to reduce noise and processing). If your use-case benefits from it, loosen the **textual allow-list** in `ResponseLoggerPassiveCheck`.

**Q: Will this respect my Burp proxy/TLS settings?**
**A:** Yes. All network calls go through **Montoya’s HTTP API**, so your proxy, certificates, and logging apply.


---

## How it works (internals)

* `Extension`
  Registers components and initializes:

    * `RdapService` → bootstraps IANA RDAP mapping (`tld -> rdap base /domain/`).
    * `RdapClient` → performs RDAP lookups via **Burp’s HTTP API**.
    * `DomainStore` → project persistence for dedupe; **cleared on startup** (debugging behavior).
    * Registers `ResponseLoggerPassiveCheck`.

* `ResponseLoggerPassiveCheck` (Passive Scan Check)
  For each textual response:

    1. Concatenates headers + body.
    2. `DomainExtractor` collects **registrable** domains from realistic contexts.
    3. Skips known noisy platform domains (configurable).
    4. Checks RDAP via `RdapClient`.
    5. If claimable **and** first time seen, raises an **Issue**.

* `DomainExtractor`
  Context-aware regexes + PSL to reduce to eTLD+1. Ignores IPs, ports, userinfo, wildcards.

* `RdapService`
  Fetches `https://data.iana.org/rdap/dns.json`, builds a TLD→base mapping.

* `RdapClient`
  RDAP GET with proper headers; handles redirects, 200-with-problem-doc, 404, and 429.

* `DomainStore`
  Uses `montoyaApi.persistence().extensionData()` to persist a `domain -> true` map.
  **Cleared on extension start** (you can remove this once you’re done debugging).

---

## Roadmap ideas

* Multi-endpoint RDAP fallback per TLD (some TLDs list multiple RDAP servers).
* Optional **tri-state** result (`CLAIMABLE / REGISTERED / UNKNOWN`) with UI filters.
* UI tab to view/export the persisted domain list and tweak the skip list at runtime.

---


## Credits

Built by Yoeri Vegt and Quack711
