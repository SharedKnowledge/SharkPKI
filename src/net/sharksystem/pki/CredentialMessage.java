package net.sharksystem.pki;

import java.io.IOException;
import java.security.PublicKey;

public interface CredentialMessage {
    /** subject - the entity that's wants to be certified */
    CharSequence getSubjectID();

    /** subject - the entity that's wants to be certified */
    CharSequence getSubjectName();

    /** subjects' public key */
    PublicKey getPublicKey();

    /** asks for a certificate to be valid since */
    long getValidSince();

    // serialize the whole message
    byte[] getMessageAsBytes() throws IOException;

    /** a random int - can be used to ensure some safety, not further semantics */
    int getRandomInt();

    /**
     * @return extra data set by application - can be null
     */
    byte[] getExtraData();
}
