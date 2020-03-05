package net.sharksystem.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

public class InMemoASAPKeyStorage implements ASAPKeyStorage {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private long timeInMillis;

    @Override
    public void storePrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public void storePublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public void setCreationTime(long timeInMillis) {
        this.timeInMillis = timeInMillis;
    }

    @Override
    public PrivateKey retrievePrivateKey() throws SharkCryptoException {
        if(this.privateKey == null) throw new SharkCryptoException("private key does not exist");
        return this.privateKey;
    }

    @Override
    public PublicKey retrievePublicKey() throws SharkCryptoException {
        if(this.publicKey == null) throw new SharkCryptoException("public key does not exist");
        return this.publicKey;
    }

    @Override
    public long getCreationTime() throws SharkCryptoException {
        if(this.publicKey == null || this.privateKey == null)
            throw new SharkCryptoException("no keys created yet");
        return this.timeInMillis;
    }
}
