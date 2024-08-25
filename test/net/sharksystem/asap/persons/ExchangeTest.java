package net.sharksystem.asap.persons;

import net.sharksystem.asap.cmdline.TCPStream;
import net.sharksystem.asap.pki.*;
import net.sharksystem.asap.utils.ASAPLogHelper;
import net.sharksystem.fs.FSUtils;
import net.sharksystem.pki.CredentialMessage;
import net.sharksystem.pki.TestConstants;
import net.sharksystem.asap.*;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;
import net.sharksystem.asap.engine.*;
import net.sharksystem.asap.utils.ASAPPeerHandleConnectionThread;
import net.sharksystem.utils.Log;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static net.sharksystem.pki.TestConstants.*;

public class ExchangeTest {
    private static final String SPECIFIC_ROOT_DIRECTORY = TestConstants.ROOT_DIRECTORY + "/asapStorageRootDirectory/";
    private static final String ALICE_ROOT_FOLDER = SPECIFIC_ROOT_DIRECTORY + ALICE_ID;
    public static final String ALICE_APP_FOLDER = ALICE_ROOT_FOLDER + "/certificateStorage";
    private static final String BOB_ROOT_FOLDER = SPECIFIC_ROOT_DIRECTORY + BOB_ID;
    public static final String BOB_APP_FOLDER = BOB_ROOT_FOLDER + "/certificateStorage";

    private static final int PORTNUMBER = 7777;

    @Test
    public void credentialCertificateExchangeOneWay() throws IOException, ASAPException, ASAPSecurityException, InterruptedException {
        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        prepare storages                                       //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        FSUtils.removeFolder(ALICE_ROOT_FOLDER); // clean previous version before
        FSUtils.removeFolder(BOB_ROOT_FOLDER); // clean previous version before

        // setup alice
        ASAPInternalStorage aliceStorage = ASAPEngineFS.getASAPStorage(
                ALICE_ID, ALICE_APP_FOLDER, ASAPCertificateStorage.PKI_APP_NAME);

        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPStorageBasedCertificates(aliceStorage, ALICE_ID, ALICE_NAME);
        net.sharksystem.asap.crypto.ASAPKeyStore aliceCryptoStorage = new InMemoASAPKeyStore(ALICE_ID);
        PersonInformationStore aliceASAPCertificateStore = new PersonStoreImplAndCertsWrapper(asapAliceCertificateStorage, aliceCryptoStorage);

        // setup bob
        ASAPInternalStorage bobStorage = ASAPEngineFS.getASAPStorage(
                BOB_ID, BOB_APP_FOLDER, ASAPCertificateStorage.PKI_APP_NAME);

        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPStorageBasedCertificates(bobStorage, BOB_ID, BOB_NAME);
        net.sharksystem.asap.crypto.ASAPKeyStore bobCryptoStorage = new InMemoASAPKeyStore(BOB_ID);
        SharkPKIFacade bobASAPCertificateStore = new SharkPKIFacadeImpl(asapBobCertificateStorage, bobCryptoStorage);

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        prepare multi engines                                  //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        Set<CharSequence> supportedFormats = new HashSet<>();
        supportedFormats.add(ASAPCertificateStorage.PKI_APP_NAME);
        supportedFormats.add(PersonInformationStore.CREDENTIAL_APP_NAME);

        CredentialReceiver aliceListener = new CredentialReceiver(aliceASAPCertificateStore);
        ASAPInternalPeer alicePeer = ASAPInternalPeerFS.createASAPPeer(
                ALICE_ID, ALICE_ROOT_FOLDER, ASAPPeerService.DEFAULT_MAX_PROCESSING_TIME, supportedFormats, aliceListener);

        //aliceEngine.activateOnlineMessages();

        SignCredentialAndReply bobListener = new SignCredentialAndReply(BOB_ROOT_FOLDER, bobASAPCertificateStore);
        ASAPInternalPeer bobPeer = ASAPInternalPeerFS.createASAPPeer(
                BOB_ID, BOB_ROOT_FOLDER, ASAPPeerService.DEFAULT_MAX_PROCESSING_TIME, supportedFormats, bobListener);
        bobListener.setAsapPeer(bobPeer);

        //bobEngine.activateOnlineMessages();

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        setup connection                                       //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        int portNumber = PORTNUMBER;
        // create connections for both sides
        TCPStream aliceChannel = new TCPStream(portNumber, true, "a2b");
        TCPStream bobChannel = new TCPStream(portNumber, false, "b2a");

        aliceChannel.start();
        bobChannel.start();

        // wait to connect
        aliceChannel.waitForConnection();
        bobChannel.waitForConnection();

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        run asap connection                                    //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        // start alice engine as thread
        ASAPPeerHandleConnectionThread aliceEngineThread = new ASAPPeerHandleConnectionThread(alicePeer,
                aliceChannel.getInputStream(), aliceChannel.getOutputStream());
        aliceEngineThread.start();

        // start bob engine as thread
        ASAPPeerHandleConnectionThread bobEngineThread = new ASAPPeerHandleConnectionThread(bobPeer,
                bobChannel.getInputStream(), bobChannel.getOutputStream());
        bobEngineThread.start();

        // wait to connect
        Thread.sleep(2000);

        // run scenario
        System.out.println("//////////////////////////////////////////////////////////////////////////////////");
        System.out.println("//                                  scenario starts                             //");
        System.out.println("//////////////////////////////////////////////////////////////////////////////////");

        // Alice send credentials to Bob
        CredentialMessage credentialMessage = aliceASAPCertificateStore.createCredentialMessage();

        // send it to bob - without traces in asap storages
        alicePeer.sendTransientASAPAssimilateMessage(PersonInformationStore.CREDENTIAL_APP_NAME,
                PersonInformationStore.CREDENTIAL_URI, credentialMessage.getMessageAsBytes());

        // wait until communication probably ends
        System.out.flush();
        System.err.flush();
        Thread.sleep(2000);
        System.out.flush();
        System.err.flush();

        // close connections: note ASAPEngine does NOT close any connection
        aliceChannel.close();
        bobChannel.close();
        System.out.flush();
        System.err.flush();
        Thread.sleep(1000);
        System.out.flush();
        System.err.flush();

        // check results

        // alice should have got a certificate of Bob
        Assert.assertTrue(aliceListener.received);
        bobASAPCertificateStore.getIdentityAssurance(ALICE_ID);

        Thread.sleep(1000);
    }

    private class SignCredentialAndReply implements ASAPChunkAssimilatedListener {
        private final String folderName;
        private final SharkPKIFacade sharkPKIFacade;
        private ASAPInternalPeer asapPeer;

        public SignCredentialAndReply(String folderName, SharkPKIFacade ASAPCertificateStore) {
            this.folderName = folderName;
            this.sharkPKIFacade = ASAPCertificateStore;
        }

        @Override
        public void chunkStored(String format, String senderE2E, String uri, int era,
                                  List<ASAPHop> asapHops) {
            Log.writeLog(this, "chunked stored called");
            ASAPMessages asapMessages =
                    ASAPLogHelper.getMessagesByChunkReceivedInfos(format, senderE2E, uri, this.folderName, era);

            Iterator<byte[]> messages = null;
            try {
                messages = asapMessages.getMessages();
                Log.writeLog(this, "#asap messages: " + asapMessages.size());
                if(messages.hasNext()) {
                    Log.writeLog(this, "create credential message object..");

                    CredentialMessageInMemo credential = new CredentialMessageInMemo(messages.next());

                    Log.writeLog(this, "..created: " + credential);

                    ASAPCertificate newCert = sharkPKIFacade.addAndSignPerson(
                            credential.getSubjectID(),
                            credential.getSubjectName(),
                            credential.getPublicKey(),
                            credential.getValidSince());

                    // return newly created certificate
                    Log.writeLog(this, "try to get asap engine for "
                            + ASAPCertificateStorage.PKI_APP_NAME);

                    ASAPEngine asapCertEngine = asapPeer.getASAPEngine(ASAPCertificateStorage.PKI_APP_NAME);

                    Log.writeLog(this,
                            "right before sending certificate as ASAP Message");
                    asapCertEngine.activateOnlineMessages(asapPeer);
                    asapCertEngine.add(ASAPCertificate.ASAP_CERTIFICATE_URI, newCert.asBytes());
                }
            } catch (Exception e) {
                Log.writeLog(this, "problems when handling incoming credential: "
                        + e.getLocalizedMessage());
            }
        }

        @Override
        public void transientMessagesReceived(ASAPMessages asapMessages, ASAPHop asapHop) throws IOException {
            Log.writeLog(this, "transientMessagesReceived");
            Log.writeLog(this, "#asap messages: " + asapMessages.size());
            Iterator<byte[]> messages = asapMessages.getMessages();
            if(messages.hasNext()) {
                Log.writeLog(this, "create credential message object..");

                try {
                    CredentialMessageInMemo credential = null;
                    credential = new CredentialMessageInMemo(messages.next());

                    Log.writeLog(this, "..created: " + credential);

                    ASAPCertificate newCert = sharkPKIFacade.addAndSignPerson(
                            credential.getSubjectID(),
                            credential.getSubjectName(),
                            credential.getPublicKey(),
                            credential.getValidSince());

                    // return newly created certificate
                    Log.writeLog(this, "try to get asap engine for "
                            + ASAPCertificateStorage.PKI_APP_NAME);

                    ASAPEngine asapCertEngine = asapPeer.getASAPEngine(ASAPCertificateStorage.PKI_APP_NAME);

                    Log.writeLog(this,
                            "right before sending certificate as ASAP Message");
                    asapCertEngine.activateOnlineMessages(asapPeer);
                    asapCertEngine.add(ASAPCertificate.ASAP_CERTIFICATE_URI, newCert.asBytes());
                } catch (Exception e) {
                    Log.writeLog(this, "problems when handling incoming credential: "
                            + e.getLocalizedMessage());
                }
            }
        }

        public void setAsapPeer(ASAPInternalPeer asapPeer) {
            this.asapPeer = asapPeer;
        }
    }

    private class CredentialReceiver implements ASAPChunkAssimilatedListener {
        private final PersonInformationStore ASAPCertificateStore;
        boolean received = false;

        public CredentialReceiver(PersonInformationStore ASAPCertificateStore) {
            this.ASAPCertificateStore = ASAPCertificateStore;
        }

        @Override
        public void chunkStored(String format, String senderE2E, String uri, int era,
                                  List<ASAPHop> asapHops) {
            Log.writeLog(this, "chunkStored");
            this.received = true;
            this.ASAPCertificateStore.incorporateReceivedCertificates();
        }

        @Override
        public void transientMessagesReceived(ASAPMessages asapMessages, ASAPHop asapHop) throws IOException {
            Log.writeLog(this, "transientMessageReceived");
            this.received = true;
            this.ASAPCertificateStore.incorporateReceivedCertificates();
        }
    }
}
