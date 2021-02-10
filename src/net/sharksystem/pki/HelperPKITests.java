package net.sharksystem.pki;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;
import net.sharksystem.asap.persons.ASAPCertificateStore;
import net.sharksystem.asap.persons.ASAPCertificateStoreImpl;
import net.sharksystem.asap.persons.CredentialMessage;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.InMemoAbstractCertificateStore;
import net.sharksystem.pki.SharkPKIComponent;

import java.io.IOException;
import java.util.Random;

public class HelperPKITests {
    public static final CharSequence FRANCIS_NAME = "Francis";
    public static final CharSequence GLORIA_NAME = "Gloria";
    public static final CharSequence HASSAN_NAME = "Hassan";
    public static final CharSequence IRIS_NAME = "Iris";

    public static void fillWithExampleData(SharkPKIComponent asapPKI)
            throws ASAPSecurityException, IOException {

        ASAPCertificateStorage certificateStorage;
        long now = System.currentTimeMillis();

        Random random = new Random(System.currentTimeMillis());
        int randomValue = random.nextInt();
        String randomString = random.toString();

        // very very unlikely, but better safe than sorry: example data must same id
        String idStart = randomString.substring(0, 3) + "_";

        ASAPCertificateStore gloriaStorage = null, hassanStorage = null, irisStorage;

        // Owner signs Francis ia(F): 10
        String francisID = idStart + FRANCIS_NAME;

        // asap storage - certificate container
        certificateStorage = new InMemoAbstractCertificateStore(francisID, FRANCIS_NAME);

        // a source of keys for francis
        ASAPKeyStore francisCryptoStorage = new InMemoASAPKeyStore(FRANCIS_NAME);

        // put certificates and keystore together and set up Francis' PKI
        ASAPCertificateStore francisStorage = new ASAPCertificateStoreImpl(certificateStorage, francisCryptoStorage);

        // produce Francis' public key which isn't used but signed by target PKI
        asapPKI.acceptAndSignCredential(
                new CredentialMessage(francisID, FRANCIS_NAME, now, francisStorage.getPublicKey()));

        // Francis signs Gloria: cef(f) = 0.5 ia(g) = 5.0
        String gloriaID = idStart + GLORIA_NAME;
        certificateStorage = new InMemoAbstractCertificateStore(gloriaID, GLORIA_NAME);
        ASAPKeyStore gloriaCryptoStorage = new InMemoASAPKeyStore(GLORIA_NAME);
        gloriaStorage = new ASAPCertificateStoreImpl(certificateStorage, gloriaCryptoStorage);
        // francis signs gloria
        ASAPCertificate asapCertificate =
                francisStorage.addAndSignPerson(gloriaID, GLORIA_NAME, gloriaStorage.getPublicKey(), now);

        // store certificate(issuer: Francis, subject: Gloria)
        asapPKI.addCertificate(asapCertificate);

        // Gloria signs Hassan: cef(g) = 0.5 ia(h) = 2.5 == 3
        String hassanID = idStart + HASSAN_NAME;
        certificateStorage = new InMemoAbstractCertificateStore(hassanID, HASSAN_NAME);
        ASAPKeyStore hassanCryptoStorage = new InMemoASAPKeyStore(HASSAN_NAME);
        hassanStorage = new ASAPCertificateStoreImpl(certificateStorage, hassanCryptoStorage);
        // gloria signs hassan
        asapCertificate = gloriaStorage.addAndSignPerson(hassanID, HASSAN_NAME, hassanStorage.getPublicKey(), now);

        // store certificate(issuer: Gloria, subject: Hassan)
        asapPKI.addCertificate(asapCertificate);

        // Hassan signs Iris: cef(h) = 0.5: ia(i) = 1.25 == 1
        String irisID = idStart + IRIS_NAME;
        certificateStorage = new InMemoAbstractCertificateStore(irisID, IRIS_NAME);
        ASAPKeyStore irisCryptoStorage = new InMemoASAPKeyStore(IRIS_NAME);
        irisStorage = new ASAPCertificateStoreImpl(certificateStorage, irisCryptoStorage);
        // hassan signs iris
        asapCertificate = hassanStorage.addAndSignPerson(irisID, IRIS_NAME, irisStorage.getPublicKey(), now);
        // store certificate(issuer: Hassan, subject: Iris)
        asapPKI.addCertificate(asapCertificate);
    }
}
