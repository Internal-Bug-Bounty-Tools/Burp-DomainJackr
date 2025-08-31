import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import java.util.List;
import java.util.Optional;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("DomainJackr");

        Logging log = montoyaApi.logging();

        // persistence-backed domain store
        DomainStore store = new DomainStore(montoyaApi);
//        store.clearAll(); // FOR DEBUGGING, DISABLE NORMALLY // CLEARS THE CACHE ON PLUGIN STARTUP

        // cache/save the RDAP DNS servers
        RdapService rdap = new RdapService(log);
        rdap.bootstrap(); // <-- runs once on startup

        // define the rdap client
        RdapClient rdapClient = new RdapClient(montoyaApi, rdap);

//        register the response-logging scanning service
        montoyaApi.scanner().registerPassiveScanCheck(
                new ResponseLoggerPassiveCheck(montoyaApi, store, rdapClient),
                ScanCheckType.PER_REQUEST // invoke once per request/response
        );
    }
}