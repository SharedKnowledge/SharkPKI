package net.sharksystem.crypto;

import net.sharksystem.SharkException;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface ASAPKeyStorage {
    void generateKeyPair() throws SharkException;

    PrivateKey getPrivateKey() throws SharkCryptoException;
    PublicKey getPublicKey() throws SharkCryptoException;
    long getCreationTime() throws SharkCryptoException;
}
