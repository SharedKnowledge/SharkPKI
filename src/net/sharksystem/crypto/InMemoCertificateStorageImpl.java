package net.sharksystem.crypto;

import net.sharksystem.asap.ASAP;

import java.io.IOException;
import java.util.*;

public class InMemoCertificateStorageImpl extends CertificateStorageImpl {
    Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap = new HashMap<>();

    public InMemoCertificateStorageImpl(CharSequence ownerID, CharSequence ownerName) {
        super(ownerID, ownerName);
    }

    @Override
    protected ASAPStorageAddress storeCertificateInStorage(ASAPCertificate cert2store) throws IOException {
        CharSequence ownerID = cert2store.getSubjectID();
        Set<ASAPCertificate> certificates = this.certificatesByOwnerIDMap.get(ownerID);
        if(certificates == null) {
            certificates = new HashSet<>();
            this.certificatesByOwnerIDMap.put(ownerID, certificates);
        }

        certificates.add(cert2store);

        return new ASAPStorageAddressImpl(
                ASAPCertificateStorage.APP_NAME,
                ASAPCertificate.ASAP_CERTIFICATE_URI,
                42); // era? always 42 - it's just for testing
    }

    @Override
    protected void removeCertificateFromStorage(ASAPCertificate cert2remove) throws IOException {
        CharSequence ownerID = cert2remove.getSubjectID();
        Set<ASAPCertificate> certificates = this.certificatesByOwnerIDMap.get(ownerID);
        if(certificates != null) {
            certificates.remove(cert2remove);
        }
    }

    @Override
    protected void readCertificatesFromStorage(Map<CharSequence, Set<ASAPCertificate>> map2Fill) {
        // make a copy
        for(CharSequence ownerName : this.certificatesByOwnerIDMap.keySet()) {
            map2Fill.put(ownerName, this.certificatesByOwnerIDMap.get(ownerName));
        }
    }

    @Override
    protected Collection<ASAPCertificate> readReceivedCertificates(
            Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap) {
        return new ArrayList<>();
    }

    @Override
    public int getEra() {
        return ASAP.INITIAL_ERA;
    }
}
