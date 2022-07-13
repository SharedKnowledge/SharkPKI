package net.sharksystem.pki;

import java.io.IOException;
import java.security.PublicKey;

public interface CredentialMessage {
    CharSequence getSubjectID();

    CharSequence getSubjectName();

    PublicKey getPublicKey();

    long getValidSince();

    byte[] getMessageAsBytes() throws IOException;

    int getRandomInt();

    /**
     *
     * @return extra data set by application - can be null
     */
    byte[] getExtraData();
}
