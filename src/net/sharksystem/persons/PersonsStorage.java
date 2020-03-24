package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.MultiASAPEngineFS;
import net.sharksystem.asap.apps.ASAPMessages;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

public interface PersonsStorage {
    CharSequence CREDENTIAL_APP_NAME = "SN2Credentials";
    CharSequence CREDENTIAL_URI = "sn2://credential";

    CharSequence getOwnerID();

    CharSequence getOwnerName();

    PrivateKey getPrivateKey() throws SharkCryptoException;

    PublicKey getPublicKey() throws SharkCryptoException;

    /**
     * @return time when key are created
     */
    long getKeysCreationTime() throws SharkCryptoException;

    ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince)
            throws SharkCryptoException, IOException;

    void setSigningFailureRate(CharSequence personID, int failureRate) throws SharkException;

    int getSigningFailureRate(CharSequence personID);

    PersonValuesImpl getPersonValuesByPosition(int position) throws SharkException;

    int getNumberOfPersons();

    int getIdentityAssurance(CharSequence userID) throws SharkException;

    List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID)
            throws SharkCryptoException;

    Collection<ASAPCertificate> getCertificateBySubject(CharSequence userID) throws SharkException;
    Collection<ASAPCertificate> getCertificateByIssuer(CharSequence userID) throws SharkException;

    void addCertificate(ASAPCertificate asapCertificate) throws IOException, SharkException;

    CredentialMessage createCredentialMessage() throws SharkCryptoException;

    /**
     * Call this method if probably new certificates are received
     * @return true if certificate of a new person received - time to call store.
     */
    boolean syncNewReceivedCertificates();

    void store(OutputStream os) throws IOException;
    void load(InputStream os) throws IOException;
}