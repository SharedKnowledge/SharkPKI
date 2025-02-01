package net.sharksystem.asap.pki;

import net.sharksystem.asap.ASAPEncounterConnectionType;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Calendar;

public interface ASAPCertificate {
    public static final String ASAP_CERTIFICATE_URI = "asap/certificate";
    int DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS = 1;

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

    ASAPEncounterConnectionType getConnectionTypeCredentialsReceived();

    boolean isIdentical(ASAPCertificate asapCertificate);
}
