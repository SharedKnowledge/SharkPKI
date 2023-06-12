package net.sharksystem.pki;

import net.sharksystem.SharkException;
import net.sharksystem.SharkTestPeerFS;
import net.sharksystem.asap.crypto.ASAPCryptoAlgorithms;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import org.junit.Test;

import java.io.IOException;
import java.security.PublicKey;

import static net.sharksystem.pki.TestConstants.ALICE_NAME;
import static net.sharksystem.pki.TestConstants.ROOT_DIRECTORY;
import static net.sharksystem.pki.TestHelper.ALICE_FOLDER;
import static net.sharksystem.pki.TestHelper.setupComponent;

public class EncryptionTests {
    /**
     * See also https://github.com/SharedKnowledge/ASAPJava/wiki/Cryptography#encrypting
     * @throws SharkException
     * @throws IOException
     */
    @Test
    public void encryptAndDecrypt() throws SharkException, IOException {
        SharkTestPeerFS.removeFolder(ROOT_DIRECTORY);
        SharkTestPeerFS aliceSharkPeer = new SharkTestPeerFS(ALICE_NAME, ALICE_FOLDER);
        SharkPKIComponent alicePKI = setupComponent(aliceSharkPeer);
        aliceSharkPeer.start();

        String idStart = HelperPKITests.fillWithExampleData(alicePKI);

        ASAPKeyStore asapKeyStore = alicePKI.getASAPKeyStore();
        String francisID = HelperPKITests.getPeerID(idStart, HelperPKITests.FRANCIS_NAME);
        PublicKey publicKeyFrancis = asapKeyStore.getPublicKey(francisID);

        byte[] encryptedData4Francis =
                ASAPCryptoAlgorithms.produceEncryptedMessagePackage(
                        TestHelper.LOST_BYTES, francisID, asapKeyStore);
    }
}
