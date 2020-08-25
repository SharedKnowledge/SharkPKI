package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
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

    Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws SharkException;
    Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws SharkException;
    ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID)
            throws SharkException;

    void addCertificate(ASAPCertificate asapCertificate) throws IOException, SharkException;

    /**
     * It is assumed this certificate is issued by storage owner. This is verified with this method or not.
     * That method is more for debugging purpose. It is used inside when re-reading certificates from external storage
     * to prevent security breeches.
     * class to assure thaty
     * @param asapCertificate
     * @throws IOException
     * @throws SharkException
     */
    boolean verifyCertificate(ASAPCertificate asapCertificate) throws SharkCryptoException, NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    CredentialMessage createCredentialMessage() throws SharkCryptoException;

    /**
     * Call this method if probably new certificates are received
     * @return true if certificate of a new person received - time to call store.
     */
    boolean syncNewReceivedCertificates();

    void store(OutputStream os) throws IOException;
    void load(InputStream os) throws IOException;
}