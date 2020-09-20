package net.sharksystem.crypto;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.util.Log;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

import static net.sharksystem.crypto.BasicCryptoKeyStorage.*;

public class InMemoASAPKeyStorage implements ASAPKeyStorage, BasicKeyStore {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private long timeInMillis = 0;

    public void generateKeyPair() throws ASAPSecurityException {
        Log.writeLog(this, "create key pair");
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new ASAPSecurityException(e.getLocalizedMessage());
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
            throw new ASAPSecurityException(re.getLocalizedMessage());
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
    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        if(this.privateKey == null) throw new ASAPSecurityException("private key does not exist");
        return this.privateKey;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                                      Basic Key Storage                                   //
    //////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public PublicKey getPublicKey(CharSequence subjectID) throws ASAPSecurityException {
        // this implementation does not store any other public key than its own
        throw new ASAPSecurityException("this implementation does not store any other public key than its own");
    }

    @Override
    public PublicKey getPublicKey() throws ASAPSecurityException {
        if(this.publicKey == null) throw new ASAPSecurityException("public key does not exist");
        return this.publicKey;
    }

    @Override
    public String getRSAEncryptionAlgorithm() {
        return DEFAULT_RSA_ENCRYPTION_ALGORITHM;
    }

    @Override
    public String getRSASigningAlgorithm() {
        return DEFAULT_SIGNATURE_ALGORITHM;
    }

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        try {
            KeyGenerator gen = KeyGenerator.getInstance(this.getSymmetricKeyType());
            gen.init(DEFAULT_AES_KEY_SIZE);
            SecretKey secretKey = gen.generateKey();
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            throw new ASAPSecurityException("cannot create symmetric key", e);
        }
    }

    @Override
    public String getSymmetricEncryptionAlgorithm() {
        return DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM;    }

    @Override
    public String getSymmetricKeyType() {
        return DEFAULT_SYMMETRIC_KEY_TYPE;
    }

    @Override
    public boolean isOwner(CharSequence charSequence) {
        return false;
    }

    @Override
    public long getCreationTime() throws ASAPSecurityException {
        if(this.publicKey == null || this.privateKey == null)
            throw new ASAPSecurityException("no keys created yet");
        return this.timeInMillis;
    }
}
