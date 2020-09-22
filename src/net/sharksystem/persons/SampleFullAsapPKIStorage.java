package net.sharksystem.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.crypto.*;

import java.io.IOException;

import static net.sharksystem.crypto.ASAPCertificateImpl.DEFAULT_SIGNATURE_METHOD;

public class SampleFullAsapPKIStorage extends FullAsapPKIStorage {
    public static final CharSequence FRANCIS_ID = "1000";
    public static final CharSequence FRANCIS_NAME = "Francis";
    public static final CharSequence GLORIA_ID = "1001";
    public static final CharSequence GLORIA_NAME = "Gloria";
    public static final CharSequence HASSAN_ID = "1002";
    public static final CharSequence HASSAN_NAME = "Hassan";
    public static final CharSequence IRIS_ID = "1003";
    public static final CharSequence IRIS_NAME = "Iris";

    public SampleFullAsapPKIStorage(CharSequence ownerID, CharSequence ownerName)
            throws ASAPSecurityException {

        super(
            new InMemoCertificateStorageImpl(ownerID, ownerName),
            new InMemoASAPKeyStorage(),
            DEFAULT_SIGNATURE_METHOD);
    }

    /**
     * fits better to android sn2
     * @param certificateStorage
     * @param asapKeyStorage
     * @param signingAlgorithm
     * @throws ASAPSecurityException
     */
    public SampleFullAsapPKIStorage(ASAPCertificateStorage certificateStorage,
                              ASAPKeyStoreWithWriteAccess asapKeyStorage,
                              String signingAlgorithm)

            throws ASAPSecurityException {

        super(certificateStorage, asapKeyStorage, signingAlgorithm);
    }

    public void fillWithExampleData() throws ASAPSecurityException, IOException {
        ASAPCertificateStorage certificateStorage;
        ASAPPKI francisStorage = null, gloriaStorage = null, hassanStorage = null, irisStorage;

        long now = System.currentTimeMillis();

        // Owner signs Francis ia(F): 10
        if(!this.getOwnerID().toString().equalsIgnoreCase(FRANCIS_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(FRANCIS_ID, FRANCIS_NAME);
            francisStorage = new ASAPPKIImpl(certificateStorage);
            this.addAndSignPerson(FRANCIS_ID, FRANCIS_NAME, francisStorage.getPublicKey(), now);
        }

        // Francis signs Gloria: cef(f) = 0.5 ia(g) = 5.0
        if(!this.getOwnerID().toString().equalsIgnoreCase(GLORIA_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(GLORIA_ID, GLORIA_NAME);
            gloriaStorage = new ASAPPKIImpl(certificateStorage);
            if(francisStorage != null) {
                ASAPCertificate asapCertificate =
                        francisStorage.addAndSignPerson(
                                GLORIA_ID, GLORIA_NAME, gloriaStorage.getPublicKey(), now);
                this.addCertificate(asapCertificate);
            }
        }

        // Gloria signs Hassan: cef(g) = 0.5 ia(h) = 2.5 == 3
        if(!this.getOwnerID().toString().equalsIgnoreCase(HASSAN_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(HASSAN_ID, HASSAN_NAME);
            hassanStorage = new ASAPPKIImpl(certificateStorage);
            if(gloriaStorage != null) {
                ASAPCertificate asapCertificate =
                        gloriaStorage.addAndSignPerson(HASSAN_ID, HASSAN_NAME, hassanStorage.getPublicKey(), now);
                this.addCertificate(asapCertificate);
            }
        }

        // Hassan signs Iris: cef(h) = 0.5: ia(i) = 1.25 == 1
        if(!this.getOwnerID().toString().equalsIgnoreCase(IRIS_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(IRIS_ID, IRIS_NAME);
            irisStorage = new ASAPPKIImpl(certificateStorage);
            if(hassanStorage != null) {
                ASAPCertificate asapCertificate =
                        hassanStorage.addAndSignPerson(IRIS_ID, IRIS_NAME, irisStorage.getPublicKey(), now);
                this.addCertificate(asapCertificate);
            }
        }
    }
}
