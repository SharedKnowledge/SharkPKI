package net.sharksystem.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface ASAPKeyStorage {
    void storePrivateKey(PrivateKey privateKey);
    void storePublicKey(PublicKey publicKey);
    void setCreationTime(long timeInMillis);

    PrivateKey retrievePrivateKey() throws SharkCryptoException;
    PublicKey retrievePublicKey() throws SharkCryptoException;
    long getCreationTime() throws SharkCryptoException;
}
