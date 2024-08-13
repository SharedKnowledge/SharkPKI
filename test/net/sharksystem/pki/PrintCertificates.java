package net.sharksystem.pki;

import net.sharksystem.SharkException;
import net.sharksystem.SharkTestPeerFS;
import net.sharksystem.asap.persons.PersonValuesImpl;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.utils.Log;
import org.junit.Test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Collection;

import static net.sharksystem.pki.HelperPKITests.FRANCIS_NAME;
import static net.sharksystem.pki.TestConstants.ALICE_NAME;
import static net.sharksystem.pki.TestConstants.ROOT_DIRECTORY;
import static net.sharksystem.pki.TestHelper.ALICE_FOLDER;
import static net.sharksystem.pki.TestHelper.setupComponent;

public class PrintCertificates {

    @Test
    public void encryptAndDecrypt() throws SharkException, IOException {
        PrintStream asapLogMessages = new PrintStream("notNeededLog.txt");
        Log.setOutStream(asapLogMessages);
        Log.setErrStream(asapLogMessages);

        SharkTestPeerFS.removeFolder(ROOT_DIRECTORY);

        SharkTestPeerFS aliceSharkPeer = new SharkTestPeerFS(ALICE_NAME, ALICE_FOLDER);
        SharkPKIComponent alicePKI = setupComponent(aliceSharkPeer);
        aliceSharkPeer.start();

        String idStart = HelperPKITests.fillWithExampleData(alicePKI);

        // get examples data
        PersonValuesImpl aPerson = alicePKI.getPersonValuesByPosition(0);
        Collection<ASAPCertificate> certificatesByIssuer = alicePKI.getCertificatesByIssuer(aPerson.getUserID());
        for(ASAPCertificate certificate : certificatesByIssuer) {
            System.out.println(PKIHelper.asapCert2String(certificate));
            System.out.println("\n");
        }
    }
}
