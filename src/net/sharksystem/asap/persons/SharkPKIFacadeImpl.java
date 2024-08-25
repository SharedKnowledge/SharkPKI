package net.sharksystem.asap.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.SharkPKIFacade;
import net.sharksystem.fs.ExtraData;
import net.sharksystem.pki.CredentialMessage;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * It is the inner facade of the overall system
 */
public class SharkPKIFacadeImpl implements SharkPKIFacade /* implements ASAPCertificateAndPersonStore */ {
    private final ASAPKeyStore asapKeyStorage;
    private final PersonStoreImplAndCertsWrapper personStoreAndCertsWrapper;

    public SharkPKIFacadeImpl(ASAPCertificateStorage certificateStorage,
                              ASAPKeyStore asapKeyStorage) throws ASAPSecurityException {

        this.personStoreAndCertsWrapper = new PersonStoreImplAndCertsWrapper(certificateStorage, asapKeyStorage);
        this.asapKeyStorage = asapKeyStorage;
    }

    public void restoreMemento(byte[] memento) throws IOException {
        if(memento == null || memento.length == 0) return;
        ByteArrayInputStream bais = new ByteArrayInputStream(memento);
        this.personStoreAndCertsWrapper.restoreFromStream(bais);
    }

    public ASAPKeyStore getASAPBasicCryptoStorage() {
        return this.asapKeyStorage;
    }

    /**
     * Find public key in certificate storage
     * @param //peerID
     * @return
     * @throws ASAPSecurityException
     */
    /*
    @Override
    public PublicKey getPublicKey(CharSequence peerID) throws ASAPSecurityException {
        if(this.isOwner(peerID)) {
            return this.getPublicKey();
        }

        int identityAssurancePeer = this.getIdentityAssurance(peerID);

        if(identityAssurancePeer != OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL) {
            Collection<ASAPCertificate> certificatesBySubject = this.getCertificatesBySubject(peerID);
            if (certificatesBySubject != null && !certificatesBySubject.isEmpty()) {
                return certificatesBySubject.iterator().next().getPublicKey();
            }
        }

        throw new ASAPSecurityException("there is no public key or no verifiable public key in this storage");
    }
     */

    @Override
    public void setMementoTarget(ExtraData extraData) {
        this.asapKeyStorage.setMementoTarget(extraData);
        this.personStoreAndCertsWrapper.setMementoTarget(extraData);
    }

    @Override
    public void generateKeyPair() throws ASAPSecurityException {
        this.asapKeyStorage.generateKeyPair();
    }

    @Override
    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        return this.asapKeyStorage.getPrivateKey();
    }

    @Override
    public PublicKey getPublicKey() throws ASAPSecurityException {
        return this.asapKeyStorage.getPublicKey();
    }

    @Override
    public PublicKey getPublicKey(CharSequence peerID) throws SharkException {
        return this.personStoreAndCertsWrapper.getPublicKey(peerID);
    }

    @Override
    public long getKeysCreationTime() throws ASAPSecurityException {
        return this.asapKeyStorage.getKeysCreationTime();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                      persons, peers and certificates                                   //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    @Override
    public CredentialMessage createCredentialMessage() throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.createCredentialMessage();
    }

    @Override
    public CharSequence getOwnerID() {
        return this.personStoreAndCertsWrapper.getOwnerID();
    }

    @Override
    public CharSequence getOwnerName() {
        return this.personStoreAndCertsWrapper.getOwnerName();
    }

    @Override
    public ASAPCertificate addAndSignPerson(CharSequence subjectID, CharSequence subjectName, PublicKey publicKey, long validSince) throws ASAPSecurityException, IOException {
        return this.personStoreAndCertsWrapper.addAndSignPerson(subjectID, subjectName, publicKey, validSince);
    }

    @Override
    public void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException {
        this.personStoreAndCertsWrapper.setSigningFailureRate(personID, failureRate);
    }

    @Override
    public int getSigningFailureRate(CharSequence personID) {
        return this.personStoreAndCertsWrapper.getSigningFailureRate(personID);
    }

    @Override
    public PersonValues getPersonValuesByPosition(int position) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getPersonValuesByPosition(position);
    }

    @Override
    public PersonValues getPersonValues(CharSequence userID) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getPersonValues(userID);
    }

    @Override
    public int getNumberOfPersons() {
        return this.personStoreAndCertsWrapper.getNumberOfPersons();
    }

    @Override
    public int getIdentityAssurance(CharSequence userID) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getIdentityAssurance(userID);
    }

    @Override
    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getIdentityAssurancesCertificationPath(userID);
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getCertificatesBySubject(subjectID);
    }

    @Override
    public Set<ASAPCertificate> getAllCertificates() {
        return this.personStoreAndCertsWrapper.getAllCertificates();
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getCertificatesByIssuer(issuerID);
    }

    @Override
    public ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID) throws ASAPSecurityException {
        return this.personStoreAndCertsWrapper.getCertificateByIssuerAndSubject(issuerID, subjectID);
    }

    @Override
    public void addCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, IOException {
        this.personStoreAndCertsWrapper.addCertificate(asapCertificate);
    }

    @Override
    public void save() {
        // keystore cannot externaly triggered to write a memento
        this.personStoreAndCertsWrapper.save();
    }

    @Override
    public ASAPKeyStore getASAPKeyStore() {
        return this.asapKeyStorage;
    }
}
