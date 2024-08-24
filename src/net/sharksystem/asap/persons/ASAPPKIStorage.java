package net.sharksystem.asap.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPCryptoAlgorithms;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.fs.ExtraData;
import net.sharksystem.utils.Log;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;

/**
 * Class uses ASAP PKI to meet requirements of ASAPKeyStore
 */
public class ASAPPKIStorage extends ASAPCertificateAndPersonStoreImpl implements
        ASAPKeyStore, ASAPCertificateAndPersonStore {

    private final ASAPKeyStore asapKeyStorage;
    private ExtraData extraData;
    private CharSequence mementoKey;

    public ASAPPKIStorage(ASAPCertificateStorage certificateStorage,
          ASAPKeyStore asapKeyStorage) throws ASAPSecurityException {

        super(certificateStorage, asapKeyStorage);
        this.asapKeyStorage = asapKeyStorage;
    }

    public void setExtraDataMementoStorage(CharSequence mementoKey, ExtraData extraData) {
        this.mementoKey = mementoKey;
        this.extraData = extraData;
    }

    public void restoreMemento(byte[] memento) throws IOException {
        if(memento == null || memento.length == 0) return;
        ByteArrayInputStream bais = new ByteArrayInputStream(memento);
        this.restoreFromStream(bais);
    }

    @Override
    void saveMemento(byte[] memento) throws SharkException, IOException {
        if(memento == null || memento.length == 0) return;
        if(this.extraData == null) {
            Log.writeLog(this, "cannot write memento - extra data missing");
        }
        this.extraData.putExtra(this.mementoKey, memento);
    }

    public ASAPKeyStore getASAPBasicCryptoStorage() {
        return this.asapKeyStorage;
    }

    /**
     * Find public key in certificate storage
     * @param peerID
     * @return
     * @throws ASAPSecurityException
     */
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

    @Override
    public boolean isOwner(CharSequence peerID) {
        return ASAPCryptoAlgorithms.sameID(this.getOwner(), peerID);
    }

    @Override
    public CharSequence getOwner() {
        return this.getOwnerID();
    }

    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        return this.asapKeyStorage.getAsymmetricEncryptionAlgorithm();
    }

    @Override
    public String getAsymmetricSigningAlgorithm() {
        return this.asapKeyStorage.getAsymmetricSigningAlgorithm();
    }

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        return this.asapKeyStorage.generateSymmetricKey();
    }

    @Override
    public String getSymmetricEncryptionAlgorithm() {
        return this.asapKeyStorage.getSymmetricEncryptionAlgorithm();
    }

    @Override
    public String getSymmetricKeyType() {
        return this.asapKeyStorage.getSymmetricKeyType();
    }

    @Override
    public int getSymmetricKeyLen() {
        return this.asapKeyStorage.getSymmetricKeyLen();
    }
}
