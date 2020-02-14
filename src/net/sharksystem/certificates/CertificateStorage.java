package net.sharksystem.certificates;

import java.io.IOException;
import java.util.Collection;

public interface CertificateStorage {
    int LOWEST_IDENTITY_ASSURANCE_LEVEL = 0;
    int HIGHEST_IDENTITY_ASSURANCE_LEVEL = 10;

    Collection<SharkCertificate> getCertificatesByOwnerID(int userID);

    ASAPStorageAddress storeCertificate(SharkCertificate sharkCertificate) throws IOException;

    void removeCertificate(SharkCertificate sharkCertificate, ASAPStorageAddress asapAddress);

    int getIdentityAssurances(int userID, PersonCertificateExchangeFailureStorage pcefs);

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
