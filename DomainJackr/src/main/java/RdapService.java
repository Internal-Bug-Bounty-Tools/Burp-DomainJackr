import burp.api.montoya.logging.Logging;
import com.google.gson.*;

import java.io.InputStreamReader;
import java.io.Reader;
import java.net.IDN;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

final class RdapService {
    private final Logging log;
    private final HttpClient http;
    private final AtomicBoolean bootstrapped = new AtomicBoolean(false);

    // tld -> "https://<rdap>/domain/"
    private volatile Map<String, String> tldToBase = Map.of();

    RdapService(Logging log) {
        this.log = log;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /** Fetch IANA RDAP bootstrap ONCE per extension start. */
    void bootstrap() {
        if (bootstrapped.getAndSet(true)) return; // already loaded

        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://data.iana.org/rdap/dns.json"))
                    .GET()
                    .build();

            HttpResponse<java.io.InputStream> rsp =
                    http.send(req, HttpResponse.BodyHandlers.ofInputStream());

            if (rsp.statusCode() != 200) {
                throw new IllegalStateException("IANA dns.json HTTP " + rsp.statusCode());
            }

            try (Reader reader = new InputStreamReader(rsp.body(), StandardCharsets.UTF_8)) {
                this.tldToBase = parseBootstrap(reader);
            }

            log.logToOutput("[RDAP] Loaded " + tldToBase.size() + " TLD mappings.");
        } catch (Exception e) {
            log.logToError("[RDAP] Bootstrap failed: " + e.getMessage());
            this.tldToBase = Map.of(); // queries will return empty if we failed
        }
    }

    /** Return the full RDAP URL for a domain, e.g. "example.com" -> "https://…/domain/example.com". */
    String rdapUrlForDomain(String domain) {
        if (domain == null) return null;
        String ascii = normalizeDomain(domain);
        if (ascii == null) return null;

        int dot = ascii.lastIndexOf('.');
        if (dot <= 0 || dot == ascii.length() - 1) return null;

        String tld = ascii.substring(dot + 1).toLowerCase(Locale.ROOT);
        String base = tldToBase.get(tld);
        if (base == null) return null;

        return base + ascii;
    }

    /** Optionally expose base endpoint for a TLD (".com" or "com"). */
    Optional<String> rdapBaseForTld(String tld) {
        if (tld == null) return Optional.empty();
        String key = tld.replaceFirst("^\\.", "").toLowerCase(Locale.ROOT);
        return Optional.ofNullable(tldToBase.get(key));
    }

    // ---- helpers ----

    private Map<String, String> parseBootstrap(Reader reader) {
        JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();
        JsonArray services = root.getAsJsonArray("services");

        Map<String, String> map = new HashMap<>();
        for (JsonElement el : services) {
            JsonArray pair = el.getAsJsonArray();
            JsonArray tlds = pair.get(0).getAsJsonArray();
            JsonArray urls = pair.get(1).getAsJsonArray();
            if (urls.isEmpty()) continue;

            String base = urls.get(0).getAsString().replaceAll("/+$", "") + "/domain/";
            for (JsonElement t : tlds) {
                String s = t.getAsString().replaceFirst("^\\.", "");
                map.put(s.toLowerCase(Locale.ROOT), base);
            }
        }
        return Collections.unmodifiableMap(map);
    }

    /** Lowercase, trim dots, and convert to ASCII (IDN). */
    static String normalizeDomain(String domain) {
        String d = domain.trim().toLowerCase(Locale.ROOT);
        d = d.replaceFirst("^\\.+", "");
        d = d.replaceFirst("\\.+$", "");
        if (d.isEmpty()) return null;
        try {
            return IDN.toASCII(d, IDN.ALLOW_UNASSIGNED);
        } catch (Exception e) {
            return null;
        }
    }
}
