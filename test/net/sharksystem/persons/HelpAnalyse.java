package net.sharksystem.persons;

import net.sharksystem.asap.ASAPEngine;
import net.sharksystem.asap.ASAPEngineFS;
import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.ASAPCertificateStorageImpl;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

public class HelpAnalyse {
    private static final String ROOT_DIRECTORY = "asapStorageRootDirectory/";
    private static final String OWNER_ID = "lUx01bs0000q1w";
    private static final String OWNER_NAME = "Alice";
    private static final String OWNER_ROOT_DIRECTORY = ROOT_DIRECTORY + OWNER_ID;
    private static final String PERSONSTORAGEFILE = OWNER_ROOT_DIRECTORY + "/sn2_personsStorageFile";

    @Test
    public void analyseTest() throws
            IOException, ASAPException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, ASAPSecurityException {



        // setup
        ASAPEngine ownerASAPStorage = ASAPEngineFS.getASAPStorage(
                OWNER_ID, OWNER_ROOT_DIRECTORY, ASAPCertificateStorage.CERTIFICATE_APP_NAME);

        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPCertificateStorageImpl(ownerASAPStorage, OWNER_ID, OWNER_NAME);
        ASAPPKI ownerASAPPKI = new ASAPPKIImpl(asapAliceCertificateStorage);


        File personsStorageFile = new File(PERSONSTORAGEFILE);
        InputStream is = new FileInputStream(personsStorageFile);
        ownerASAPPKI.load(is);
        is.close();

        ownerASAPPKI.getIdentityAssurance("jav_Francis");
    }
}
