package net.sharksystem.crypto;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPStorage;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;

public interface ASAPCertificateStorage {
    String ASAP_CERIFICATE_APP = "asapCertificates";

    Collection<ASAPCertificate> getCertificatesByOwnerID(int userID);

    ASAPStorage getASAPStorage();
    public int getOwnerID();
    public CharSequence getOwnerName();


    ASAPStorageAddress storeCertificate(ASAPCertificate ASAPCertificate) throws IOException;

    void removeCertificate(ASAPCertificate cert2remove, ASAPStorageAddress asapAddress) throws IOException;

    int getIdentityAssurances(int userID, PersonCertificateExchangeFailureStorage pcefs) throws SharkException;

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
