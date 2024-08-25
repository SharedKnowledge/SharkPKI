package net.sharksystem.asap.pki;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.persons.PersonValues;
import net.sharksystem.fs.ExtraData;
import net.sharksystem.pki.CredentialMessage;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Set;

public interface SharkPKIFacade {
    /**
     * Create a credential message.
     * @return
     * @deprecated there is no need to produce such a message. This component can be asked to send a credentials with
     * a transient asap message. Much easier.
     */
    CredentialMessage createCredentialMessage() throws ASAPSecurityException;

    /**
     * Component has data to persist. Set a target. All data get lost.
     * @param sharkPeerExtraData
     */
    void setMementoTarget(ExtraData sharkPeerExtraData);

    /**
     * Force component to create a new key pair.
     */
    void generateKeyPair() throws ASAPSecurityException;

    /**
     * Get owner id.
     * @return
     */
    CharSequence getOwnerID();

    /**
     * Get owner name
     * @return
     */
    CharSequence getOwnerName();

    /**
     * Return private key. That's dangerous.
     * @return
     * @deprecated There is no need to deal with a private key at all. This component does the work and can keep
     * it internally
     */
    PrivateKey getPrivateKey() throws ASAPSecurityException;

    /**
     * Get components own public key.
     * @return
     * @deprecated There is no need to deal with a private key at all. This component does the work and can keep
     * it internally
     */
    PublicKey getPublicKey() throws ASAPSecurityException;

    PublicKey getPublicKey(CharSequence peerID) throws SharkException;

    /**
     * Key pair creation time is returned
     * @return
     */
    long getKeysCreationTime() throws ASAPSecurityException;

    /**
     * Credential information are accepted as valid. A certificate is issued. That's the very heart of a PKI. Be
     * extremely cautious using it.
     * @param subjectID
     * @param subjectName
     * @param publicKey
     * @param validSince
     * @return
     */
    ASAPCertificate addAndSignPerson(CharSequence subjectID, CharSequence subjectName, PublicKey publicKey, long validSince) throws ASAPSecurityException, IOException;

    void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException;

    int getSigningFailureRate(CharSequence personID);

    PersonValues getPersonValuesByPosition(int position) throws ASAPSecurityException;

    PersonValues getPersonValues(CharSequence peerID) throws ASAPSecurityException;

    int getNumberOfPersons();

    int getIdentityAssurance(CharSequence userID) throws ASAPSecurityException;

    List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID) throws ASAPSecurityException;

    Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws ASAPSecurityException;

    Set<ASAPCertificate> getAllCertificates();

    Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws ASAPSecurityException;

    ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID) throws ASAPSecurityException;

    /**
     * Add a certificate. Usually, app developers will not need it since this component creates and disseminates
     * certificates. Anyway, if there is a reason to introduce a certificate from the outside world into the Shark
     * realm - here is the methode.
     * @param asapCertificate
     * @deprecated see description.
     */
    void addCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, IOException;

    /**
     * Force to write a memento when possible.
     */
    void save();

    /**
     * Get the key store used to keep
     * @return
     */
    ASAPKeyStore getASAPKeyStore();
}
