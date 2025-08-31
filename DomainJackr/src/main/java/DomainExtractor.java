// DomainExtractor.java (strict, context-aware)
// deps: Apache HttpClient 5.x for PSL (same as before)

import org.apache.hc.client5.http.psl.PublicSuffixMatcher;
import org.apache.hc.client5.http.psl.PublicSuffixMatcherLoader;

import java.net.IDN;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DomainExtractor {

    // ---- URL / header / CSP contexts ----
    private static final Pattern URL_HOST = Pattern.compile(
            "(?i)\\b(?:https?|wss?|ftp)://([^/\\s\"'<>]+)"
    );
    private static final Pattern SCHEMELESS_HOST = Pattern.compile(
            "(?i)(?<!\\w)//([^/\\s\"'<>]+)"
    );
    private static final Pattern EMAIL_DOMAIN = Pattern.compile(
            "(?i)[\\p{L}0-9._%+-]+@([\\p{L}0-9.-]+\\.[\\p{L}]{2,63})"
    );
    private static final Pattern HEADER_HOST = Pattern.compile(
            "(?im)^(?:host|origin|referer|content-location)\\s*:\\s*([^\\s:/]+)"
    );
    // Capture the value portion of CSP directives; we’ll split tokens inside it.
    private static final Pattern CSP_DIRECTIVE = Pattern.compile(
            "(?i)\\b(?:default-src|connect-src|script-src|img-src|media-src|font-src|style-src|frame-src|child-src|form-action|frame-ancestors|manifest-src)\\s+([^;]+)"
    );
    private static final Pattern CSS_URL = Pattern.compile(
            "(?i)url\\(\\s*([\"']?)([^\\s\"')]+)\\1\\s*\\)"
    );

    // For stripping wildcard prefixes (*.example.com) and userinfo/port.
    private static final Pattern WILDCARD_PREFIX = Pattern.compile("^\\*\\.?");

    // Quick IP checks to drop them (we only return domains)
    private static final Pattern IPV4 = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)$"
    );
    private static final Pattern BRACKETED_IPV6 = Pattern.compile("^\\[.+\\]$");

    private static final int IDN_FLAGS = IDN.ALLOW_UNASSIGNED | IDN.USE_STD3_ASCII_RULES;

    private final PublicSuffixMatcher psl;

    public DomainExtractor() {
        this(PublicSuffixMatcherLoader.getDefault());
    }

    public DomainExtractor(PublicSuffixMatcher psl) {
        this.psl = Objects.requireNonNull(psl, "psl");
    }

    /** Extract unique registrable domains (eTLD+1) from realistic URL/host contexts only. */
    public List<String> extractDomains(String input) {
        if (input == null || input.isEmpty()) return List.of();

        Set<String> out = new LinkedHashSet<>();

        // 1) Full URLs
        collectFromMatcher(URL_HOST.matcher(input), out);

        // 2) Scheme-relative //host/path
        collectFromMatcher(SCHEMELESS_HOST.matcher(input), out);

        // 3) Emails
        collectFromMatcher(EMAIL_DOMAIN.matcher(input), out);

        // 4) Common headers (works because your logger puts headers as plain text)
        collectFromMatcher(HEADER_HOST.matcher(input), out);

        // 5) CSS url(...)
        Matcher css = CSS_URL.matcher(input);
        while (css.find()) {
            String value = css.group(2);
            String host = hostFromUrlLike(value);
            if (host != null) addIfRegistrable(host, out);
        }

        // 6) CSP directive token lists
        Matcher csp = CSP_DIRECTIVE.matcher(input);
        while (csp.find()) {
            String list = csp.group(1);
            for (String token : list.split("\\s+")) {
                String host = hostFromCspToken(token);
                if (host != null) addIfRegistrable(host, out);
            }
        }

        return new ArrayList<>(out);
    }

    // ---- helpers ----

    private void collectFromMatcher(Matcher m, Set<String> out) {
        while (m.find()) {
            String authorityOrHost = m.group(1);
            String host = hostFromAuthority(authorityOrHost);
            if (host != null) addIfRegistrable(host, out);
        }
    }

    /** Normalize authority to a host: strip userinfo, port, brackets; ignore IPs. */
    private String hostFromAuthority(String authority) {
        if (authority == null || authority.isEmpty()) return null;
        String a = authority.trim();

        // Remove userinfo if present
        int at = a.lastIndexOf('@');
        if (at != -1) a = a.substring(at + 1);

        // IPv6 in brackets? treat as IP (skip)
        if (BRACKETED_IPV6.matcher(a).matches()) return null;

        // Strip path/query/hash if any (for sloppy matches)
        int slash = a.indexOf('/');
        if (slash != -1) a = a.substring(0, slash);

        // Strip port (host:port)
        int colon = a.indexOf(':');
        if (colon != -1) a = a.substring(0, colon);

        a = trimDots(a.toLowerCase(Locale.ROOT));
        if (a.isEmpty()) return null;

        if (IPV4.matcher(a).matches()) return null; // drop IPs

        return a;
    }

    /** Extract host from a bare URL-ish string (may be absolute or scheme-relative). */
    private String hostFromUrlLike(String s) {
        if (s == null || s.isEmpty()) return null;
        Matcher m1 = URL_HOST.matcher(s);
        if (m1.find()) return hostFromAuthority(m1.group(1));
        Matcher m2 = SCHEMELESS_HOST.matcher(s);
        if (m2.find()) return hostFromAuthority(m2.group(1));
        // Not a URL; ignore
        return null;
    }

    /** Parse CSP source token to host if applicable (ignores keywords/schemes). */
    private String hostFromCspToken(String token) {
        if (token == null || token.isEmpty()) return null;
        String t = token.trim().replaceAll("^['\"]|['\"]$", ""); // strip quotes

        // Skip keywords/schemes
        String lower = t.toLowerCase(Locale.ROOT);
        if (lower.equals("'self'") || lower.equals("'none'") ||
                lower.startsWith("data:") || lower.startsWith("blob:") ||
                lower.startsWith("filesystem:") || lower.startsWith("mediastream:") ||
                lower.startsWith("https:") || lower.startsWith("http:") ||
                lower.startsWith("wss:")   || lower.startsWith("ws:")) {
            // If it's a scheme alone, try to parse as URL to get host.
            String host = hostFromUrlLike(t);
            return host; // may be null
        }

        // Wildcards: *.example.com -> example.com (we'll reduce later via PSL anyway)
        t = WILDCARD_PREFIX.matcher(t).replaceFirst("");

        // If token looks like host[:port][/...], extract authority portion
        return hostFromAuthority(t);
    }

    private void addIfRegistrable(String host, Set<String> out) {
        String ascii;
        try {
            ascii = IDN.toASCII(host, IDN_FLAGS);
        } catch (Exception e) {
            return; // bad IDN
        }
        ascii = trimDots(ascii);
        if (ascii.isEmpty()) return;

        // Minimal heuristic to drop super-short SLDs like "a.kg" if you want:
        // (Uncomment if needed)
        // int dot = ascii.lastIndexOf('.');
        // if (dot > 0 && ascii.substring(0, dot).length() < 2) return;

        // check if the string contains a dot
        if (ascii.indexOf('.') == -1) return;

        // PSL reduction
        String root = psl.getDomainRoot(ascii);
        if (root == null || root.isEmpty() || root.indexOf('.') == -1) return;
        out.add(root.toLowerCase(Locale.ROOT));
    }

    private static String trimDots(String s) {
        String t = s.replaceFirst("^\\.+", "").replaceFirst("\\.+$", "");
        if (t.contains("..")) t = t.replaceAll("\\.+", ".").replaceAll("^\\.|\\.$", "");
        return t;
    }
}
