package net.sharksystem.persons;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface ASAPKeyStoreWriteAccess {
    void setPrivateKey(PrivateKey privateKey);
    void setPublicKey(PublicKey publicKey);
}
