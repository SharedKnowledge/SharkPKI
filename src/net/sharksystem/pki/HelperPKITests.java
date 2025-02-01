package net.sharksystem.pki;

import net.sharksystem.asap.ASAPEncounterConnectionType;
import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;
import net.sharksystem.asap.persons.PersonInformationStore;
import net.sharksystem.asap.persons.PersonStoreImplAndCertsWrapper;
import net.sharksystem.asap.persons.SharkPKIFacadeImpl;
import net.sharksystem.asap.pki.CredentialMessageInMemo;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.InMemoCertificates;

import java.io.IOException;
import java.util.Random;

public class HelperPKITests {
    public static final CharSequence FRANCIS_NAME = "Francis";
    public static final CharSequence GLORIA_NAME = "Gloria";
    public static final CharSequence HASSAN_NAME = "Hassan";
    public static final CharSequence IRIS_NAME = "Iris";

    public static String getPeerID(String idStart, CharSequence peerName) {
        return idStart + peerName;
    }

    public static String fillWithExampleData(SharkPKIComponent asapPKI)
            throws ASAPException, IOException {

        ASAPCertificateStorage certificateStorage;
        long now = System.currentTimeMillis();

        Random random = new Random(System.currentTimeMillis());
        int randomValue = random.nextInt();
        String randomString = random.toString();

        // very very unlikely, but better safe than sorry: example data must same id
        String idStart = randomString.substring(0, 3) + "_";

        SharkPKIFacadeImpl gloriaStorage = null;
        SharkPKIFacadeImpl hassanPKI = null;
        PersonInformationStore irisStorage;

        // Owner signs Francis ia(F): 10
        String francisID = getPeerID(idStart, FRANCIS_NAME);

        // asap storage - certificate container
        certificateStorage = new InMemoCertificates(francisID, FRANCIS_NAME);

        // a source of keys for francis
        ASAPKeyStore francisCryptoStorage = new InMemoASAPKeyStore(FRANCIS_NAME);

        // put certificates and keystore together and set up Francis' PKI
        SharkPKIFacadeImpl francisStorage = new SharkPKIFacadeImpl(certificateStorage, francisCryptoStorage);

        // produce Francis' public key which isn't used but signed by target PKI
        asapPKI.acceptAndSignCredential(
                new CredentialMessageInMemo(francisID, FRANCIS_NAME, now, francisCryptoStorage.getPublicKey()));

        // Francis signs Gloria: cef(f) = 0.5 ia(g) = 5.0
        String gloriaID = getPeerID(idStart,  GLORIA_NAME);
        certificateStorage = new InMemoCertificates(gloriaID, GLORIA_NAME);
        ASAPKeyStore gloriaCryptoStorage = new InMemoASAPKeyStore(GLORIA_NAME);
        gloriaStorage = new SharkPKIFacadeImpl(certificateStorage, gloriaCryptoStorage);
        // francis signs gloria
        ASAPCertificate asapCertificate =
                francisStorage.addAndSignPerson(gloriaID, GLORIA_NAME, gloriaCryptoStorage.getPublicKey(), now, ASAPEncounterConnectionType.UNKNOWN);

        // store certificate(issuer: Francis, subject: Gloria)
        asapPKI.addCertificate(asapCertificate);

        // Gloria signs Hassan: cef(g) = 0.5 ia(h) = 2.5 == 3
        String hassanID = getPeerID(idStart, HASSAN_NAME);
        certificateStorage = new InMemoCertificates(hassanID, HASSAN_NAME);
        ASAPKeyStore hassanCryptoStorage = new InMemoASAPKeyStore(HASSAN_NAME);
        hassanPKI = new SharkPKIFacadeImpl(certificateStorage, hassanCryptoStorage);
        // gloria signs hassan
        asapCertificate = gloriaStorage.addAndSignPerson(hassanID, HASSAN_NAME, hassanPKI.getPublicKey(), now, ASAPEncounterConnectionType.UNKNOWN);

        // store certificate(issuer: Gloria, subject: Hassan)
        asapPKI.addCertificate(asapCertificate);

        // Hassan signs Iris: cef(h) = 0.5: ia(i) = 1.25 == 1
        String irisID = getPeerID(idStart, IRIS_NAME);
        certificateStorage = new InMemoCertificates(irisID, IRIS_NAME);
        ASAPKeyStore irisKeyStore = new InMemoASAPKeyStore(IRIS_NAME);
        irisStorage = new PersonStoreImplAndCertsWrapper(certificateStorage, irisKeyStore);
        // hassan signs iris
        asapCertificate = hassanPKI.addAndSignPerson(irisID, IRIS_NAME, irisKeyStore.getPublicKey(), now, ASAPEncounterConnectionType.UNKNOWN);
        // store certificate(issuer: Hassan, subject: Iris)
        asapPKI.addCertificate(asapCertificate);

        return idStart;
    }
}
