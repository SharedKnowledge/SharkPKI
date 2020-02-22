package net.sharksystem.crypto;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.persons.PersonsStorage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

public interface ASAPCertificateStorage {
    String ASAP_CERIFICATE_APP = "asapCertificates";

    Collection<ASAPCertificate> getCertificatesByOwnerID(int userID);

    ASAPStorage getASAPStorage();
    int getOwnerID();
    CharSequence getOwnerName();

    ASAPStorageAddress storeCertificate(ASAPCertificate ASAPCertificate) throws IOException;

    void removeCertificate(ASAPCertificate cert2remove) throws IOException;

    int getIdentityAssurances(int userID, PersonsStorage personsStorage) throws SharkCryptoException;

    List<Integer> getIdentityAssurancesCertificationPath(int userID, PersonsStorage personsStorage)
            throws SharkCryptoException;

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
