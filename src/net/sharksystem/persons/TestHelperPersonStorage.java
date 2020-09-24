package net.sharksystem.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.crypto.*;

import java.io.IOException;
import java.util.Random;

public class TestHelperPersonStorage {
    public static final CharSequence FRANCIS_NAME = "Francis";
    public static final CharSequence GLORIA_NAME = "Gloria";
    public static final CharSequence HASSAN_NAME = "Hassan";
    public static final CharSequence IRIS_NAME = "Iris";

    public static void fillWithExampleData(FullAsapPKIStorage asapPKI)
            throws ASAPSecurityException, IOException {

        ASAPCertificateStorage certificateStorage;
        long now = System.currentTimeMillis();

        Random random = new Random(System.currentTimeMillis());
        int randomValue = random.nextInt();
        String randomString = random.toString();

        // very very unlikely, but better safe than sorry: example data must same id
        String idStart = randomString.substring(0, 3) + "_";

        ASAPPKI gloriaStorage = null, hassanStorage = null, irisStorage;

        // Owner signs Francis ia(F): 10
        String francisID = idStart + FRANCIS_NAME;

        // asap storage - certificate container
        certificateStorage = new InMemoCertificateStorageImpl(francisID, FRANCIS_NAME);

        // a source of keys for francis
        ASAPBasicCryptoStorage francisCryptoStorage = new InMemoASAPKeyStorage();

        // put certificates and keystore together and set up Francis' PKI
        ASAPPKI francisStorage = new ASAPPKIImpl(certificateStorage, francisCryptoStorage);

        // produce Francis' public key which isn't used but signed by target PKI
        asapPKI.addAndSignPerson(francisID, FRANCIS_NAME, francisStorage.getPublicKey(), now);

        // Francis signs Gloria: cef(f) = 0.5 ia(g) = 5.0
        String gloriaID = idStart + GLORIA_NAME;
        certificateStorage = new InMemoCertificateStorageImpl(gloriaID, GLORIA_NAME);
        ASAPBasicCryptoStorage gloriaCryptoStorage = new InMemoASAPKeyStorage();
        gloriaStorage = new ASAPPKIImpl(certificateStorage, gloriaCryptoStorage);
        // francis signs gloria
        ASAPCertificate asapCertificate =
                francisStorage.addAndSignPerson(gloriaID, GLORIA_NAME, gloriaStorage.getPublicKey(), now);

        // store certificate(issuer: Francis, subject: Gloria)
        asapPKI.addCertificate(asapCertificate);

        // Gloria signs Hassan: cef(g) = 0.5 ia(h) = 2.5 == 3
        String hassanID = idStart + HASSAN_NAME;
        certificateStorage = new InMemoCertificateStorageImpl(hassanID, HASSAN_NAME);
        ASAPBasicCryptoStorage hassanCryptoStorage = new InMemoASAPKeyStorage();
        hassanStorage = new ASAPPKIImpl(certificateStorage, hassanCryptoStorage);
        // gloria signs hassan
        asapCertificate = gloriaStorage.addAndSignPerson(hassanID, HASSAN_NAME, hassanStorage.getPublicKey(), now);

        // store certificate(issuer: Gloria, subject: Hassan)
        asapPKI.addCertificate(asapCertificate);

        // Hassan signs Iris: cef(h) = 0.5: ia(i) = 1.25 == 1
        String irisID = idStart + IRIS_NAME;
        certificateStorage = new InMemoCertificateStorageImpl(irisID, IRIS_NAME);
        ASAPBasicCryptoStorage irisCryptoStorage = new InMemoASAPKeyStorage();
        irisStorage = new ASAPPKIImpl(certificateStorage, irisCryptoStorage);
        // hassan signs iris
        asapCertificate = hassanStorage.addAndSignPerson(irisID, IRIS_NAME, irisStorage.getPublicKey(), now);
        // store certificate(issuer: Hassan, subject: Iris)
        asapPKI.addCertificate(asapCertificate);
    }
}
