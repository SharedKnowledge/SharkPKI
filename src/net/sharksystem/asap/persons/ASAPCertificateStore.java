package net.sharksystem.asap.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPCertificate;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Collection;
import java.util.List;

public interface ASAPCertificateStore {
    CharSequence CREDENTIAL_APP_NAME = "SN2Credentials";
    CharSequence CREDENTIAL_URI = "sn2://credential";

    CharSequence getOwnerID();

    CharSequence getOwnerName();

    PrivateKey getPrivateKey() throws ASAPSecurityException;

    PublicKey getPublicKey() throws ASAPSecurityException;

    /**
     * @return time when key are created
     */
    long getKeysCreationTime() throws ASAPSecurityException;

    ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince)
            throws ASAPSecurityException, IOException;

    void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException;

    int getSigningFailureRate(CharSequence personID);

    PersonValuesImpl getPersonValuesByPosition(int position) throws ASAPSecurityException;

    int getNumberOfPersons();

    int getIdentityAssurance(CharSequence userID) throws ASAPSecurityException;

    List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID)
            throws ASAPSecurityException;

    Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws ASAPSecurityException;
    Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws ASAPSecurityException;
    ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID)
            throws ASAPSecurityException;

    void addCertificate(ASAPCertificate asapCertificate) throws IOException, ASAPSecurityException;

    /**
     * It is assumed this certificate is issued by storage owner. This is verified with this method or not.
     * That method is more for debugging purpose. It is used inside when re-reading certificates from external storage
     * to prevent security breeches.
     * class to assure thaty
     * @param asapCertificate
     * @throws IOException
     * @throws ASAPSecurityException
     */
    boolean verifyCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    CredentialMessage createCredentialMessage() throws ASAPSecurityException;

    /**
     * Call this method if probably new certificates are received
     * @return true if certificate of a new person received - time to call store.
     */
    boolean syncNewReceivedCertificates();

    void store(OutputStream os) throws IOException;
    void load(InputStream os) throws IOException;
}