package net.sharksystem;

import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPPeer;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.asap.crypto.*;
import net.sharksystem.asap.persons.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Collection;
import java.util.List;

/**
 * Shark component facade of this certificate / PKI component
 */
@ASAPFormats(formats = {ASAPCertificateStore.CREDENTIAL_APP_NAME, ASAPCertificateStorage.CERTIFICATE_APP_NAME})
public class SharkCertificateComponent implements SharkComponent,
        ASAPKeyStore, ASAPCertificateStore {

    private FullAsapPKIStorage asapPKIStorage = null;

    @Override
    public void onStart(ASAPPeer asapPeer) throws SharkException {
        try {
            ASAPStorage asapStorage = asapPeer.getASAPStorage(asapPeer.getPeerName());
            ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPAbstractCertificateStore(asapStorage, asapPeer.getPeerName(), asapPeer.getPeerName());

            InMemoASAPKeyStore inMemoASAPKeyStore = new InMemoASAPKeyStore(asapPeer.getPeerName());

            this.asapPKIStorage = new FullAsapPKIStorage(asapAliceCertificateStorage, inMemoASAPKeyStore);
        } catch (IOException | ASAPException e) {
            throw new SharkException(e);
        }
    }

    private void checkStatus() throws SharkStatusException {
        if(this.asapPKIStorage == null) {
            throw new SharkStatusException("ASAP peer not started component not yet initialized");
        }
    }

    @Override
    public PublicKey getPublicKey(CharSequence charSequence) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPublicKey(charSequence);
    }

    @Override
    public boolean isOwner(CharSequence charSequence) {
        this.checkStatus();
        return this.asapPKIStorage.isOwner(charSequence);
    }

    @Override
    public CharSequence getOwner() {
        this.checkStatus();
        return this.asapPKIStorage.getOwner();
    }

    @Override
    public void generateKeyPair() throws ASAPSecurityException {
        this.checkStatus();
        this.asapPKIStorage.generateKeyPair();
    }

    @Override
    public CharSequence getOwnerID() {
        this.checkStatus();
        return this.asapPKIStorage.getOwnerID();
    }

    @Override
    public CharSequence getOwnerName() {
        this.checkStatus();
        return this.asapPKIStorage.getOwnerName();
    }

    @Override
    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPrivateKey();
    }

    @Override
    public PublicKey getPublicKey() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPublicKey();
    }

    @Override
    public long getKeysCreationTime() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getKeysCreationTime();
    }

    @Override
    public ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince) throws ASAPSecurityException, IOException {
        this.checkStatus();
        return this.asapPKIStorage.addAndSignPerson(userID, userName, publicKey, validSince);
    }

    @Override
    public void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException {
        this.checkStatus();
        this.asapPKIStorage.setSigningFailureRate(personID, failureRate);
    }

    @Override
    public int getSigningFailureRate(CharSequence personID) {
        this.checkStatus();
        return this.asapPKIStorage.getSigningFailureRate(personID);
    }

    @Override
    public PersonValuesImpl getPersonValuesByPosition(int position) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPersonValuesByPosition(position);
    }

    @Override
    public int getNumberOfPersons() {
        this.checkStatus();
        return this.asapPKIStorage.getNumberOfPersons();
    }

    @Override
    public int getIdentityAssurance(CharSequence userID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getIdentityAssurance(userID);
    }

    @Override
    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getIdentityAssurancesCertificationPath(userID);
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getCertificatesBySubject(subjectID);
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getCertificatesByIssuer(issuerID);
    }

    @Override
    public ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getCertificateByIssuerAndSubject(issuerID, subjectID);
    }

    @Override
    public void addCertificate(ASAPCertificate asapCertificate) throws IOException, ASAPSecurityException {
        this.checkStatus();
        this.asapPKIStorage.addCertificate(asapCertificate);
    }

    @Override
    public boolean verifyCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        this.checkStatus();
        return this.asapPKIStorage.verifyCertificate(asapCertificate);
    }

    @Override
    public CredentialMessage createCredentialMessage() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.createCredentialMessage();
    }

    @Override
    public boolean syncNewReceivedCertificates() {
        this.checkStatus();
        return this.asapPKIStorage.syncNewReceivedCertificates();
    }

    @Override
    public void store(OutputStream os) throws IOException {
        this.checkStatus();
        this.asapPKIStorage.store(os);
    }

    @Override
    public void load(InputStream is) throws IOException {
        this.checkStatus();
        this.asapPKIStorage.load(is);
    }

    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        this.checkStatus();
        return this.asapPKIStorage.getAsymmetricEncryptionAlgorithm();
    }

    @Override
    public String getAsymmetricSigningAlgorithm() {
        this.checkStatus();
        return this.asapPKIStorage.getAsymmetricSigningAlgorithm();
    }

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.generateSymmetricKey();
    }

    @Override
    public String getSymmetricEncryptionAlgorithm() {
        this.checkStatus();
        return this.asapPKIStorage.getSymmetricEncryptionAlgorithm();
    }

    @Override
    public String getSymmetricKeyType() {
        this.checkStatus();
        return this.asapPKIStorage.getSymmetricKeyType();
    }

    @Override
    public int getSymmetricKeyLen() {
        this.checkStatus();
        return this.asapPKIStorage.getSymmetricKeyLen();
    }
}
