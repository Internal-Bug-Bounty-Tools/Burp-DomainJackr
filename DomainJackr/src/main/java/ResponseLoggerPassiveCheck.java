// ResponseLoggerPassiveCheck.java
// Passive scan check that files issues instead of logging domains.

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static burp.api.montoya.scanner.AuditResult.auditResult;

public final class ResponseLoggerPassiveCheck implements PassiveScanCheck {
    private final MontoyaApi api;
    private final DomainStore store;
    private final RdapClient rdapClient;

    // Allow-list of textual content types we actually want to scan.
    private static final Set<String> TEXTUAL_EXACT = Set.of(
            "text/plain",
            "text/html",
            "text/css",
            "text/csv",
            "text/javascript",
            "application/javascript",
            "application/ecmascript",
            "application/json",
            "application/ld+json",
            "application/x-ndjson",
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/graphql",
            "application/x-www-form-urlencoded"
    );
    private static final String[] TEXTUAL_PREFIXES = new String[] { "text/" };

    // Skip list of registrable domains (eTLD+1) that are commonly
    // provider-owned/CDN platforms and produce noise for takeover checks.
    // Extend this as you like.
    private static final Set<String> SKIP_ETLD1 = Set.of(
            "amazonaws.com", "appspot.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
            "cloudfront.net", "cloudflare.net", "fastly.net", "akamai.net", "akamaihd.net","fbcdn.net",
            "edgesuite.net", "edgekey.net", "jsdelivr.net", "stackpathcdn.com", "cdn77.org", "www.google",
            "herokuapp.com", "vercel.app", "netlify.app", "azurewebsites.net", "windows.net",
            "google.com", "cloudflareinsights.com", "twimg.com", "cloudflare.com", "google-analytics.com",
            "freshworks.com", "twitter.com", "githubassets.com", "vimeo.com", "jquery.com", "msauth.net", "msftauth.net",
            "onetrust.com", "optimizely.com", "zendesk.com", "shopify.com", "wp.com", "prmcdn.io", "stripe.com",
            "cookielaw.org", "awswaf.com", "googletagmanager.com", "website-files.com", "googletagservices.com",
            "fontawesome.com", "hubspot.com", "typekit.com", "unpkg.com", "atlassian.com", "oktacdn.com"
    );

    public ResponseLoggerPassiveCheck(MontoyaApi api, DomainStore store, RdapClient rdapClient) {
        this.api = api;
        this.store = store;
        this.rdapClient = rdapClient;
    }

    @Override
    public String checkName() {
        return "DomainJackr: Response Logger";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse base) {
        HttpResponse resp = base.response();
        if (resp == null) {
            return auditResult(List.of());
        }

        // Skip non-text/binary-ish responses early
        if (!isProbablyTextual(resp)) {
            return auditResult(List.of());
        }

        // Build a single string (headers + body) to feed DomainExtractor
        StringBuilder sb = new StringBuilder(51200);
        sb.append("[DomainJackr] Passive log for ")
                .append(base.request().url())
                .append(" — Status ").append(resp.statusCode()).append('\n');

        for (HttpHeader h : resp.headers()) {
            sb.append(h.name()).append(": ").append(h.value()).append('\n');
        }
        sb.append("\n").append(resp.bodyToString());

        List<String> found = new DomainExtractor().extractDomains(sb.toString());

        List<AuditIssue> issues = new ArrayList<>();
        for (String domain : found) {
            // ⬅️ Skip noisy provider/CDN domains
            if (isSkippedDomain(domain)) {
                continue;
            }

            // Only act on first sighting in this Burp project
            if (!store.markIfNew(domain)) continue;

            boolean claimable = false;
            try {
                claimable = rdapClient.isClaimable(domain);
            } catch (Exception e) {
                api.logging().logToError("[DomainJackr] RDAP check failed for " + domain + ": " + e.getMessage());
            }
            if (!claimable) continue;

            // Compose issue
            String baseUrl = base.request().url();
            String escapedDomain = h(domain);
            String escapedUrl = h(baseUrl);

            String detail =
                    "<p>The application references the domain <code>" + escapedDomain + "</code>, " +
                            "which appears <strong>unregistered</strong> according to RDAP (HTTP 404 or equivalent).</p>" +
                            "<p><b>First seen in:</b> " + escapedUrl + "</p>" +
                            "<p>This can enable a domain takeover if an attacker registers the domain and serves " +
                            "controlled content (e.g., scripts, CSS, images) or captures email.</p>";

            String remediation =
                    "<ul>" +
                            "<li>Register the domain if it is intended to be owned.</li>" +
                            "<li>Otherwise, remove/replace references (links, assets, CSP, redirects, emails).</li>" +
                            "<li>Consider CSP hardening and Subresource Integrity where applicable.</li>" +
                            "</ul>";

            AuditIssue issue = AuditIssue.auditIssue(
                    "Possible domain takeover: " + escapedDomain,
                    detail,
                    remediation,
                    baseUrl,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    "Unregistered domains referenced by an application may be registered by attackers to hijack resources or email.",
                    "Own required domains and eliminate stale references to reduce takeover risk.",
                    AuditIssueSeverity.LOW,
                    List.of(base)   // evidence
            );

            issues.add(issue);
        }

        return auditResult(issues);
    }

    // --- helpers ---

    /** Only scan "probably textual" responses; skip everything else. */
    private static boolean isProbablyTextual(HttpResponse resp) {
        String ct = null;
        for (HttpHeader h : resp.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                ct = h.value();
                break;
            }
        }
        if (ct == null) return true; // no header -> treat as text (common on misconfigured servers)

        String s = ct.toLowerCase(Locale.ROOT).trim();
        int sc = s.indexOf(';');                  // strip params: "type/subtype; charset=utf-8"
        if (sc != -1) s = s.substring(0, sc).trim();

        for (String p : TEXTUAL_PREFIXES) {
            if (s.startsWith(p)) return true;
        }
        if (TEXTUAL_EXACT.contains(s)) return true;

        // Suffix-based structured text types (e.g., application/manifest+json)
        if (s.endsWith("+json") || s.endsWith("+xml")) return true;

        return false;
    }

    /** Returns true if the registrable domain (eTLD+1) is on the skip list. */
    private static boolean isSkippedDomain(String registrableDomain) {
        if (registrableDomain == null || registrableDomain.isEmpty()) return false;
        String d = registrableDomain.toLowerCase(Locale.ROOT);
        // DomainExtractor already returns eTLD+1; equality check is enough.
        if (d.contains("amazonaws")) return false;
        return SKIP_ETLD1.contains(d);
    }

    // Minimal HTML escaper for details/remediation (Burp allows simple HTML only).
    private static String h(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
