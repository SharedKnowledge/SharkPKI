package net.sharksystem.pki;

import net.sharksystem.asap.ASAPSecurityException;

public interface SharkPKIDebugSupport {
    CredentialMessage createCredentialMessage() throws ASAPSecurityException;
}
