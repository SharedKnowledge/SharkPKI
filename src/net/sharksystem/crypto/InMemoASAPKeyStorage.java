package net.sharksystem.crypto;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.util.Log;
import net.sharksystem.persons.ASAPBasicCryptoStorage;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

public class InMemoASAPKeyStorage implements ASAPBasicCryptoStorage {
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

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    protected void setTimeInMillis(long timeInMillis) {
        this.timeInMillis = timeInMillis;
    }

    @Override
    public long getCreationTime() throws ASAPSecurityException {
        if(this.publicKey == null || this.privateKey == null)
            throw new ASAPSecurityException("no keys created yet");
        return this.timeInMillis;
    }

    @Override
    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        if(this.privateKey == null) throw new ASAPSecurityException("private key does not exist");
        return this.privateKey;
    }

    @Override
    public PublicKey getPublicKey() throws ASAPSecurityException {
        if(this.publicKey == null) throw new ASAPSecurityException("public key does not exist");
        return this.publicKey;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                                      Basic Crypto Setting                                //
    //////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        try {
            KeyGenerator gen = KeyGenerator.getInstance(this.getSymmetricKeyType());
            gen.init(this.getSymmetricKeyLen());
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
    public int getSymmetricKeyLen() {
        return DEFAULT_SYMMETRIC_KEY_SIZE;
    }

    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        return DEFAULT_ASYMMETRIC_ENCRYPTION_ALGORITHM;
    }

    @Override
    public String getAsymmetricSigningAlgorithm() {
        return DEFAULT_ASYMMETRIC_SIGNATURE_ALGORITHM;
    }
}
