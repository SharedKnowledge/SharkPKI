package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;

public interface PersonsStorage {
    int getOwnerUserID();

    CharSequence getOwnerName();

    PrivateKey getPrivateKey();

    PublicKey getPublicKey();

    ASAPCertificate addAndSignPerson(int bobID, CharSequence bobName, PublicKey bobPublicKey)
            throws SharkCryptoException, IOException;

    PersonValuesImpl getPersonValuesByPosition(int position) throws SharkException;

    int getNumberOfPersons();

    int getIdentityAssurance(int userID) throws SharkException;

    Collection<ASAPCertificate> getCertificate(int userID) throws SharkException;

    void setCertificateExchangeFailure(int personID, int failureRate) throws SharkException;

    int getCertificateExchangeFailure(int personID);

    void addCertificate(ASAPCertificate asapCertificate) throws IOException, SharkException;
}