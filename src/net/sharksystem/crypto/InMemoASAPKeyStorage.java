package net.sharksystem.crypto;

import net.sharksystem.SharkException;
import net.sharksystem.asap.util.Log;

import java.security.*;

public class InMemoASAPKeyStorage implements ASAPKeyStorage {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private long timeInMillis = 0;

    public void generateKeyPair() throws SharkException {
        Log.writeLog(this, "create key pair");
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new SharkException(e.getLocalizedMessage());
        }

        SecureRandom secRandom = new SecureRandom();
        try {
            keyGen.initialize(2048, secRandom);
            KeyPair rsaKeyPair = keyGen.generateKeyPair();
            this.privateKey = rsaKeyPair.getPrivate();
            this.publicKey = rsaKeyPair.getPublic();
            this.timeInMillis = System.currentTimeMillis();
        }
        catch(RuntimeException re) {
            throw new SharkException(re.getLocalizedMessage());
        }
    }

    protected void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    protected void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    protected void setTimeInMillis(long timeInMillis) {
        this.timeInMillis = timeInMillis;
    }

    @Override
    public PrivateKey getPrivateKey() throws SharkCryptoException {
        if(this.privateKey == null) throw new SharkCryptoException("private key does not exist");
        return this.privateKey;
    }

    @Override
    public PublicKey getPublicKey() throws SharkCryptoException {
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
