package net.sharksystem.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.crypto.*;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;

/**
 * Class uses ASAP PKI to meet requirements of BasicKeyStore
 */
public class FullAsapPKIStorage extends ASAPPKIImpl implements BasicKeyStore {

    public FullAsapPKIStorage(ASAPCertificateStorage certificateStorage,
                                  ASAPKeyStoreWithWriteAccess asapKeyStorage,
                              String signingAlgorithm)

            throws ASAPSecurityException {

        super(certificateStorage, asapKeyStorage, signingAlgorithm);
    }

/*
    public FullAsapPKIStorage(ASAPCertificateStorage certificateStorage)
            throws ASAPSecurityException {

        super(certificateStorage);
    }
 */

    /**
     * Find public key in certificate storage
     * @param peerID
     * @return
     * @throws ASAPSecurityException
     */
    @Override
    public PublicKey getPublicKey(CharSequence peerID) throws ASAPSecurityException {
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
    public String getRSAEncryptionAlgorithm() {
        return BasicKeyStore.DEFAULT_RSA_ENCRYPTION_ALGORITHM;
    }

    @Override
    public String getRSASigningAlgorithm() {
        return BasicKeyStore.DEFAULT_SIGNATURE_ALGORITHM;
    }

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        return ASAPCryptoAlgorithms.generateSymmetricKey(
                this.getSymmetricKeyType(),
                this.getSymmetricKeyLen());
    }

    @Override
    public String getSymmetricEncryptionAlgorithm() {
        return BasicKeyStore.DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM;
    }

    @Override
    public String getSymmetricKeyType() {
        return BasicKeyStore.DEFAULT_SYMMETRIC_KEY_TYPE;
    }

    @Override
    public int getSymmetricKeyLen() {
        return BasicKeyStore.DEFAULT_AES_KEY_SIZE;
    }
}
