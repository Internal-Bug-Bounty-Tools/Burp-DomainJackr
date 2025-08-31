// DomainStore.java
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.util.Objects;

public final class DomainStore {
    private static final String NS_KEY = "domainjackr";
    private static final String DOMAINS_KEY = "domains";

    private final PersistedObject root;    // project-level store
    private final PersistedObject ns;      // our namespace
    private PersistedObject domains;       // child object mapping domain -> boolean

    public DomainStore(MontoyaApi api) {
        Objects.requireNonNull(api, "api");
        this.root = api.persistence().extensionData();

        PersistedObject existingNs = root.getChildObject(NS_KEY);
        if (existingNs == null) {
            existingNs = PersistedObject.persistedObject();   // STATIC call
            root.setChildObject(NS_KEY, existingNs);
        }
        this.ns = existingNs;

        PersistedObject existingDomains = ns.getChildObject(DOMAINS_KEY);
        if (existingDomains == null) {
            existingDomains = PersistedObject.persistedObject(); // STATIC call
            ns.setChildObject(DOMAINS_KEY, existingDomains);
        }
        this.domains = existingDomains;
    }

    /** Remove all saved domains (called on plugin start per your request). */
    public synchronized void clearAll() {
        ns.deleteChildObject(DOMAINS_KEY);
        this.domains = PersistedObject.persistedObject(); // STATIC call
        ns.setChildObject(DOMAINS_KEY, this.domains);
    }

    /**
     * Return true iff this domain wasn't seen before (and mark it as seen).
     * The domain string should already be normalized/punycode for stable keys.
     */
    public synchronized boolean markIfNew(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        Boolean present = domains.getBoolean(domain);
        if (present != null && present) {
            return false; // already saved
        }
        domains.setBoolean(domain, true);
        return true;
    }
}
