// RdapClient.java
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.util.List;

public final class RdapClient {
    private static final int MAX_REDIRECTS = 3;

    private final MontoyaApi api;
    private final RdapService rdapService;

    public RdapClient(MontoyaApi api, RdapService rdapService) {
        this.api = api;
        this.rdapService = rdapService;
    }

    /** true => domain appears claimable (i.e., not found in RDAP) */
    public boolean isClaimable(String domain) {
        String rdapUrl = rdapService.rdapUrlForDomain(domain);
        if (rdapUrl == null) {
            api.logging().logToOutput("[RDAP] No RDAP mapping for: " + domain);
            return false; // unknown TLD/invalid
        }
        return isClaimableUrl(rdapUrl);
    }

    /** Same logic, direct RDAP URL (e.g., https://rdap.verisign.com/com/v1/domain/example.com). */
    public boolean isClaimableUrl(String rdapUrl) {
        try {
            String current = rdapUrl;

            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                HttpRequest req = HttpRequest.httpRequestFromUrl(current)
                        .withAddedHeader("Accept", "application/rdap+json, application/json;q=0.8, */*;q=0.1");

                HttpRequestResponse rr = api.http().sendRequest(req);
                HttpResponse resp = rr.response();
                if (resp == null) {
                    api.logging().logToError("[RDAP] No response for " + current);
                    return false;
                }

                short code = resp.statusCode();

                // Canonical "not found"
                if (code == 404) {
                    return true;
                }

                // Follow redirects (limited)
                if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                    String loc = headerValue(resp.headers(), "Location");
                    if (loc == null || loc.isBlank()) {
                        api.logging().logToError("[RDAP] Redirect without Location for " + current);
                        return false;
                    }
                    current = resolve(current, loc);
                    continue;
                }

                // Success → inspect body (Problem Document vs. Domain Object)
                if (code == 200) {
                    String body = safeBody(resp);
                    if (body == null || body.isBlank()) {
                        return false;
                    }
                    Boolean claimable = interpret200(body);
                    return claimable != null && claimable;
                }

                // Rate limited / others → conservative false
                if (code == 429) {
                    String ra = headerValue(resp.headers(), "Retry-After");
                    api.logging().logToOutput("[RDAP] 429 rate limited for " + current +
                            (ra != null ? " (Retry-After: " + ra + ")" : ""));
                    return false;
                }

                // Any other status → treat as not claimable (unknown)
                api.logging().logToOutput("[RDAP] Non-200/404 status " + code + " for " + current);
                return false;
            }

            api.logging().logToError("[RDAP] Too many redirects for " + rdapUrl);
            return false;
        } catch (Exception e) {
            api.logging().logToError("[RDAP] Request failed for " + rdapUrl + ": " + e.getMessage());
            return false;
        }
    }

    // --- helpers ---

    /** Return true if 200 body indicates "not found" (problem doc 404), false if domain object; null if unknown. */
    private Boolean interpret200(String body) {
        try {
            JsonElement rootEl = JsonParser.parseString(body);
            if (!rootEl.isJsonObject()) return null;
            JsonObject obj = rootEl.getAsJsonObject();

            // RDAP Problem Document (RFC 9083 §6)
            if (obj.has("errorCode")) {
                int ec = safeInt(obj, "errorCode", -1);
                if (ec == 404) return true;   // server used 200 with embedded 404
                return false;                 // other errors → treat as not claimable
            }

            // RDAP Domain Object
            String ocn = safeString(obj, "objectClassName");
            if (ocn != null && "domain".equalsIgnoreCase(ocn)) {
                return false; // it's a real domain object → registered
            }

            // Some servers may return "help" or other objects
            return false;
        } catch (Exception e) {
            // Malformed JSON → unknown
            return null;
        }
    }

    private static String safeBody(HttpResponse resp) {
        try {
            return resp.bodyToString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String headerValue(List<HttpHeader> headers, String name) {
        for (HttpHeader h : headers) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    private static String resolve(String base, String location) {
        try {
            return URI.create(base).resolve(location).toString();
        } catch (Exception e) {
            return location; // best-effort
        }
    }

    private static String safeString(JsonObject o, String k) {
        try {
            return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static int safeInt(JsonObject o, String k, int def) {
        try {
            return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsInt() : def;
        } catch (Exception e) {
            return def;
        }
    }
}
