package net.sharksystem.asap.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.InMemoAbstractCertificateStore;

import java.io.IOException;

public class SampleASAPPKIStorage extends ASAPPKIStorage {
    public static final CharSequence FRANCIS_ID = "1000";
    public static final CharSequence FRANCIS_NAME = "Francis";
    public static final CharSequence GLORIA_ID = "1001";
    public static final CharSequence GLORIA_NAME = "Gloria";
    public static final CharSequence HASSAN_ID = "1002";
    public static final CharSequence HASSAN_NAME = "Hassan";
    public static final CharSequence IRIS_ID = "1003";
    public static final CharSequence IRIS_NAME = "Iris";

    public SampleASAPPKIStorage(CharSequence ownerID, CharSequence ownerName)
            throws ASAPSecurityException {

        super(
            new InMemoAbstractCertificateStore(ownerID, ownerName),
            new InMemoASAPKeyStore(ownerID));
    }

    public void fillWithExampleData() throws ASAPSecurityException, IOException {
        ASAPCertificateStorage certificateStorage;
        ASAPCertificateAndPersonStore francisStorage = null, gloriaStorage = null, hassanStorage = null, irisStorage;

        long now = System.currentTimeMillis();

        ASAPKeyStore asapKeyStorage = this.getASAPBasicCryptoStorage();

        // Owner signs Francis ia(F): 10
        if(!this.getOwnerID().toString().equalsIgnoreCase(FRANCIS_ID.toString())) {
            certificateStorage = new InMemoAbstractCertificateStore(FRANCIS_ID, FRANCIS_NAME);
            francisStorage = new ASAPCertificateAndPersonStoreImpl(certificateStorage, asapKeyStorage);
            this.addAndSignPerson(FRANCIS_ID, FRANCIS_NAME, francisStorage.getPublicKey(), now);
        }

        // Francis signs Gloria: cef(f) = 0.5 ia(g) = 5.0
        if(!this.getOwnerID().toString().equalsIgnoreCase(GLORIA_ID.toString())) {
            certificateStorage = new InMemoAbstractCertificateStore(GLORIA_ID, GLORIA_NAME);
            gloriaStorage = new ASAPCertificateAndPersonStoreImpl(certificateStorage, asapKeyStorage);
            if(francisStorage != null) {
                ASAPCertificate asapCertificate =
                        francisStorage.addAndSignPerson(
                                GLORIA_ID, GLORIA_NAME, gloriaStorage.getPublicKey(), now);
                this.addCertificate(asapCertificate);
            }
        }

        // Gloria signs Hassan: cef(g) = 0.5 ia(h) = 2.5 == 3
        if(!this.getOwnerID().toString().equalsIgnoreCase(HASSAN_ID.toString())) {
            certificateStorage = new InMemoAbstractCertificateStore(HASSAN_ID, HASSAN_NAME);
            hassanStorage = new ASAPCertificateAndPersonStoreImpl(certificateStorage, asapKeyStorage);
            if(gloriaStorage != null) {
                ASAPCertificate asapCertificate =
                        gloriaStorage.addAndSignPerson(HASSAN_ID, HASSAN_NAME, hassanStorage.getPublicKey(), now);
                this.addCertificate(asapCertificate);
            }
        }

        // Hassan signs Iris: cef(h) = 0.5: ia(i) = 1.25 == 1
        if(!this.getOwnerID().toString().equalsIgnoreCase(IRIS_ID.toString())) {
            certificateStorage = new InMemoAbstractCertificateStore(IRIS_ID, IRIS_NAME);
            irisStorage = new ASAPCertificateAndPersonStoreImpl(certificateStorage, asapKeyStorage);
            if(hassanStorage != null) {
                ASAPCertificate asapCertificate =
                        hassanStorage.addAndSignPerson(IRIS_ID, IRIS_NAME, irisStorage.getPublicKey(), now);
                this.addCertificate(asapCertificate);
            }
        }
    }
}
