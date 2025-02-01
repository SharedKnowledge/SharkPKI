package net.sharksystem.pki;

import net.sharksystem.asap.ASAPEncounterConnectionType;

import java.io.IOException;
import java.security.PublicKey;

public interface CredentialMessage {
    /** subject - the entity that's wants to be certified */
    CharSequence getSubjectID();

    /** subject - the entity that's wants to be certified */
    CharSequence getSubjectName();

    void setSubjectName(CharSequence newName);

    /** subjects' public key */
    PublicKey getPublicKey();

    /** asks for a certificate to be valid since */
    long getValidSince();

    // serialize the whole message
    byte[] getMessageAsBytes() throws IOException;

    /**
     * @return extra data set by application - can be null
     */
    byte[] getExtraData();

    /**
     *
     * @return connection over which those credentials are received
     */
    ASAPEncounterConnectionType getConnectionTypeCredentialReceived();
}
