package net.sharksystem.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Calendar;

public interface ASAPCertificate {
    public static final String ASAP_CERTIFICATE = "asap/certificate";

    /**
     * @return person which public key is matched with its name
     */
    CharSequence getSubjectID();

    CharSequence getSubjectName();

    /**
     * @return person who signed this certificate
     */
    CharSequence getIssuerID();

    CharSequence getIssuerName();

    Calendar getValidSince();

    Calendar getValidUntil();

    byte[] asBytes();

    boolean verify(PublicKey publicKeyIssuer) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    ASAPStorageAddress getASAPStorageAddress();

    PublicKey getPublicKey();
}
