package net.sharksystem.crypto;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.persons.PersonsStorage;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;

public interface ASAPCertificateStorage {
    String ASAP_CERIFICATE_APP = "asapCertificates";

    Collection<ASAPCertificate> getCertificatesByOwnerID(int userID);

    ASAPStorage getASAPStorage();
    int getOwnerID();
    CharSequence getOwnerName();

    ASAPStorageAddress storeCertificate(ASAPCertificate ASAPCertificate) throws IOException;

    void removeCertificate(ASAPCertificate cert2remove) throws IOException;

    int getIdentityAssurances(int userID, PersonsStorage personsStorage) throws SharkException;

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
