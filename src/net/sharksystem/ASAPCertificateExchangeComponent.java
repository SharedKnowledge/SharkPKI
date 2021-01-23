package net.sharksystem;

import net.sharksystem.asap.ASAPPeer;
import net.sharksystem.asap.crypto.ASAPCertificateStorage;
import net.sharksystem.asap.persons.ASAPCertificateStore;

import java.util.HashSet;
import java.util.Set;

public class ASAPCertificateExchangeComponent implements SharkComponent {
    @Override
    public Set<CharSequence> getSupportedFormats() {
        Set<CharSequence> formatSet = new HashSet<>();
        formatSet.add(ASAPCertificateStorage.CERTIFICATE_APP_NAME);
        formatSet.add(ASAPCertificateStore.CREDENTIAL_APP_NAME);
        return formatSet;
    }

    @Override
    public SharkComponentInterface getInterface() {
        return null; // TODO
    }

    @Override
    public void onStart(ASAPPeer asapPeer) throws SharkException {
        // TODO add listener to asap peer etc.
    }
}
