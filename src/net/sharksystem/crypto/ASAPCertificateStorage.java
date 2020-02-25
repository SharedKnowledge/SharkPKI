package net.sharksystem.crypto;

import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.persons.PersonsStorage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

public interface ASAPCertificateStorage {
    String APP_NAME = "asapCertificates";

    Collection<ASAPCertificate> getCertificatesByOwnerID(CharSequence userID);

    Collection<ASAPCertificate> getCertificatesBySignerID(CharSequence userID);

    CharSequence getOwnerID();
    CharSequence getOwnerName();

    ASAPStorageAddress storeCertificate(ASAPCertificate asapCertificate) throws IOException;

    void removeCertificate(ASAPCertificate cert2remove) throws IOException;

    int getIdentityAssurances(CharSequence userID, PersonsStorage personsStorage) throws SharkCryptoException;

    List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID, PersonsStorage personsStorage)
            throws SharkCryptoException;

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
