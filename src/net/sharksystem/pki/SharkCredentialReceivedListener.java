package net.sharksystem.pki;

import net.sharksystem.asap.persons.CredentialMessage;

public interface SharkCredentialReceivedListener {
    void credentialReceived(CredentialMessage credentialMessage);
}
