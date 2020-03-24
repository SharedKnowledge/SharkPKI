package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.*;
import net.sharksystem.asap.apps.ASAPMessages;
import net.sharksystem.asap.util.ASAPEngineThread;
import net.sharksystem.asap.util.Helper;
import net.sharksystem.asap.util.Log;
import net.sharksystem.cmdline.TCPChannel;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.ASAPCertificateStorageImpl;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import static net.sharksystem.asap.MultiASAPEngineFS.DEFAULT_MAX_PROCESSING_TIME;

public class ExchangeTest {
    public static final String ALICE_ROOT_FOLDER = "tests/Alice";
    public static final String ALICE_APP_FOLDER = ALICE_ROOT_FOLDER + "/certificateStorage";
    public static final String BOB_ROOT_FOLDER = "tests/Bob";
    public static final String BOB_APP_FOLDER = BOB_ROOT_FOLDER + "/certificateStorage";
    public static final String ALICE_ID = "AliceID";
    public static final String BOB_ID = "BobID";
    public static final String ALICE_NAME = "Alice";
    public static final String BOB_NAME = "Bob";
    private static final int PORTNUMBER = 7777;

    @Test
    public void credentialCertificateExchangeOneWay() throws IOException, ASAPException, SharkException, InterruptedException {
        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        prepare storages                                       //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        ASAPEngineFS.removeFolder(ALICE_ROOT_FOLDER); // clean previous version before
        ASAPEngineFS.removeFolder(BOB_ROOT_FOLDER); // clean previous version before

        // setup alice
        ASAPStorage aliceStorage = ASAPEngineFS.getASAPStorage(
                ALICE_ID, ALICE_APP_FOLDER, ASAPCertificateStorage.CERTIFICATE_APP_NAME);

        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPCertificateStorageImpl(aliceStorage, ALICE_ID, ALICE_NAME);
        PersonsStorage alicePersonsStorage = new PersonsStorageImpl(asapAliceCertificateStorage);

        // setup bob
        ASAPStorage bobStorage = ASAPEngineFS.getASAPStorage(
                BOB_ID, BOB_APP_FOLDER, ASAPCertificateStorage.CERTIFICATE_APP_NAME);

        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPCertificateStorageImpl(bobStorage, BOB_ID, BOB_NAME);
        PersonsStorage bobPersonsStorage = new PersonsStorageImpl(asapBobCertificateStorage);

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        prepare multi engines                                  //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        Set<CharSequence> supportedFormats = new HashSet<>();
        supportedFormats.add(ASAPCertificateStorage.CERTIFICATE_APP_NAME);
        supportedFormats.add(PersonsStorage.CREDENTIAL_APP_NAME);

        CredentialReceiver aliceListener = new CredentialReceiver(alicePersonsStorage);
        MultiASAPEngineFS aliceEngine = MultiASAPEngineFS_Impl.createMultiEngine(
                ALICE_ID, ALICE_ROOT_FOLDER, DEFAULT_MAX_PROCESSING_TIME, supportedFormats, aliceListener);

        //aliceEngine.activateOnlineMessages();

        SignCredentialAndReply bobListener = new SignCredentialAndReply(BOB_ROOT_FOLDER, bobPersonsStorage);
        MultiASAPEngineFS bobEngine = MultiASAPEngineFS_Impl.createMultiEngine(
                BOB_ID, BOB_ROOT_FOLDER, DEFAULT_MAX_PROCESSING_TIME, supportedFormats, bobListener);
        bobListener.setMultiEngine(bobEngine);

        //bobEngine.activateOnlineMessages();

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        setup connection                                       //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        int portNumber = PORTNUMBER;
        // create connections for both sides
        TCPChannel aliceChannel = new TCPChannel(portNumber, true, "a2b");
        TCPChannel bobChannel = new TCPChannel(portNumber, false, "b2a");

        aliceChannel.start();
        bobChannel.start();

        // wait to connect
        aliceChannel.waitForConnection();
        bobChannel.waitForConnection();

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //                                        run asap connection                                    //
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        // start alice engine as thread
        ASAPEngineThread aliceEngineThread = new ASAPEngineThread(aliceEngine,
                aliceChannel.getInputStream(), aliceChannel.getOutputStream());
        aliceEngineThread.start();

        // start bob engine as thread
        ASAPEngineThread bobEngineThread = new ASAPEngineThread(bobEngine,
                bobChannel.getInputStream(), bobChannel.getOutputStream());
        bobEngineThread.start();

        // wait to connect
        Thread.sleep(2000);

        // run scenario
        System.out.println("//////////////////////////////////////////////////////////////////////////////////");
        System.out.println("//                                  scenario starts                             //");
        System.out.println("//////////////////////////////////////////////////////////////////////////////////");

        // Alice send credentials to Bob
        CredentialMessage credentialMessage = alicePersonsStorage.createCredentialMessage();

        // send it to bob - without traces in asap storages
        aliceEngine.sendOnlineASAPAssimilateMessage(PersonsStorage.CREDENTIAL_APP_NAME,
                PersonsStorage.CREDENTIAL_URI, credentialMessage.getMessageAsBytes());

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
        bobPersonsStorage.getIdentityAssurance(ALICE_ID);

        Thread.sleep(1000);
    }

    private class SignCredentialAndReply implements ASAPChunkReceivedListener {
        private final String folderName;
        private final PersonsStorage personsStorage;
        private MultiASAPEngineFS multiEngine;

        public SignCredentialAndReply(String folderName, PersonsStorage personsStorage) {
            this.folderName = folderName;
            this.personsStorage = personsStorage;
        }

        @Override
        public void chunkReceived(String format, String sender, String uri, int era) {
            ASAPMessages asapMessages =
                    Helper.getMessageByChunkReceivedInfos(format, sender, uri, this.folderName, era);

            Iterator<byte[]> messages = null;
            try {
                messages = asapMessages.getMessages();
                Log.writeLog(this, "#asap messages: " + asapMessages.size());
                if(messages.hasNext()) {
                    Log.writeLog(this, "create credential message object..");

                    CredentialMessage credential = new CredentialMessage(messages.next());

                    Log.writeLog(this, "..created: " + credential);

                    ASAPCertificate newCert = personsStorage.addAndSignPerson(
                            credential.getOwnerID(),
                            credential.getOwnerName(),
                            credential.getPublicKey(),
                            credential.getValidSince());

                    // return newly created certificate
                    Log.writeLog(this, "try to get asap engine for "
                            + ASAPCertificateStorage.CERTIFICATE_APP_NAME);

                    ASAPEngine asapCertEngine = multiEngine.getASAPEngine(ASAPCertificateStorage.CERTIFICATE_APP_NAME);

                    Log.writeLog(this,
                            "right before sending certificate as ASAP Message");
                    asapCertEngine.activateOnlineMessages(multiEngine);
                    asapCertEngine.add(ASAPCertificate.ASAP_CERTIFICATE_URI, newCert.asBytes());
                }
            } catch (Exception e) {
                Log.writeLog(this, "problems when handling incoming credential: "
                        + e.getLocalizedMessage());
            }
        }

        public void setMultiEngine(MultiASAPEngineFS multiEngine) {
            this.multiEngine = multiEngine;
        }
    }

    private class CredentialReceiver implements ASAPChunkReceivedListener {
        private final PersonsStorage personsStorage;
        boolean received = false;

        public CredentialReceiver(PersonsStorage personsStorage) {
            this.personsStorage = personsStorage;
        }

        @Override
        public void chunkReceived(String format, String sender, String uri, int era) {
            this.received = true;
            this.personsStorage.syncNewReceivedCertificates();
        }
    }
}
