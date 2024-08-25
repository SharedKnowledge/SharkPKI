package net.sharksystem.pki;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.pki.SharkPKIFacade;
import net.sharksystem.asap.utils.PeerIDHelper;
import net.sharksystem.fs.ExtraData;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

class ASAPKeyStoreWrapper implements ASAPKeyStore {
    private final ASAPKeyStore asapKeyStore;
    private final SharkPKIFacade sharkPKIFacade;

    public ASAPKeyStoreWrapper(ASAPKeyStore asapKeyStore, SharkPKIFacade sharkPKIFacade) {
        this.asapKeyStore = asapKeyStore;
        this.sharkPKIFacade = sharkPKIFacade;
    }

    @Override
    public PublicKey getPublicKey(CharSequence peerID) throws ASAPSecurityException {
        if(PeerIDHelper.sameID(peerID, this.getOwner())) {
            return this.getPublicKey();
        }
        try {
            return this.sharkPKIFacade.getPublicKey(peerID);
        } catch (SharkException e) {
            throw new ASAPSecurityException(e);
        }
    }

    @Override
    public PublicKey getPublicKey() throws ASAPSecurityException {
        return this.asapKeyStore.getPublicKey();
    }

    ///// following - pure delegate

    @Override
    public boolean isOwner(CharSequence charSequence) {
        return this.asapKeyStore.isOwner(charSequence);
    }

    @Override
    public CharSequence getOwner() {
        return this.asapKeyStore.getOwner();
    }

    @Override
    public void generateKeyPair() throws ASAPSecurityException {
        this.asapKeyStore.generateKeyPair();
    }

    @Override
    public void setMementoTarget(ExtraData extraData) {
        this.asapKeyStore.setMementoTarget(extraData);
    }

    @Override
    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        return this.asapKeyStore.getPrivateKey();
    }

    @Override
    public long getKeysCreationTime() throws ASAPSecurityException {
        return this.asapKeyStore.getKeysCreationTime();
    }

    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        return this.asapKeyStore.getAsymmetricEncryptionAlgorithm();
    }

    @Override
    public String getAsymmetricSigningAlgorithm() {
        return this.asapKeyStore.getAsymmetricSigningAlgorithm();
    }

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        return this.asapKeyStore.generateSymmetricKey();
    }

    @Override
    public String getSymmetricEncryptionAlgorithm() {
        return this.asapKeyStore.getSymmetricEncryptionAlgorithm();
    }

    @Override
    public String getSymmetricKeyType() {
        return this.asapKeyStore.getSymmetricKeyType();
    }

    @Override
    public int getSymmetricKeyLen() {
        return this.asapKeyStore.getSymmetricKeyLen();
    }
}
