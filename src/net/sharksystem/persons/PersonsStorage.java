package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;

public interface PersonsStorage {
    CharSequence getOwnerUserID();

    CharSequence getOwnerName();

    PrivateKey getPrivateKey();

    PublicKey getPublicKey();

    ASAPCertificate addAndSignPerson(CharSequence bobID, CharSequence bobName, PublicKey bobPublicKey)
            throws SharkCryptoException, IOException;

    PersonValuesImpl getPersonValuesByPosition(int position) throws SharkException;

    int getNumberOfPersons();

    int getIdentityAssurance(CharSequence userID) throws SharkException;

    Collection<ASAPCertificate> getCertificate(CharSequence userID) throws SharkException;

    void setCertificateExchangeFailure(CharSequence personID, int failureRate) throws SharkException;

    int getCertificateExchangeFailure(CharSequence personID);

    void addCertificate(ASAPCertificate asapCertificate) throws IOException, SharkException;
}