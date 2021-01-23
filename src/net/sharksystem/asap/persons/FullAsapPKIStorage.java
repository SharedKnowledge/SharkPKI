package net.sharksystem.asap.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPCryptoAlgorithms;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.*;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Collection;

/**
 * Class uses ASAP PKI to meet requirements of BasicKeyStore
 */
public class FullAsapPKIStorage extends ASAPCertificateStoreImpl implements ASAPKeyStore {
    private final ASAPKeyStore asapKeyStorage;

    public FullAsapPKIStorage(ASAPCertificateStorage certificateStorage,
                              ASAPKeyStore asapKeyStorage)

            throws ASAPSecurityException {

        super(certificateStorage, asapKeyStorage);
        this.asapKeyStorage = asapKeyStorage;
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
