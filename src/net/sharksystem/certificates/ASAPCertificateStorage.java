package net.sharksystem.certificates;

import net.sharksystem.asap.ASAPStorage;

import java.io.IOException;
import java.util.Collection;

public interface ASAPCertificateStorage {
    int LOWEST_IDENTITY_ASSURANCE_LEVEL = 0;
    int HIGHEST_IDENTITY_ASSURANCE_LEVEL = 10;

    Collection<ASAPCertificate> getCertificatesByOwnerID(int userID);

    ASAPStorage getASAPStorage();

    ASAPStorageAddress storeCertificate(ASAPCertificate ASAPCertificate) throws IOException;

    void removeCertificate(ASAPCertificate cert2remove, ASAPStorageAddress asapAddress) throws IOException;

    int getIdentityAssurances(int userID, PersonCertificateExchangeFailureStorage pcefs);

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
