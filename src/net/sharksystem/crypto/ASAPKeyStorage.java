package net.sharksystem.crypto;

import net.sharksystem.asap.ASAPSecurityException;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface ASAPKeyStorage {
    void generateKeyPair() throws ASAPSecurityException;

    PrivateKey getPrivateKey() throws ASAPSecurityException;
    PublicKey getPublicKey() throws ASAPSecurityException;
    long getCreationTime() throws ASAPSecurityException;
}
