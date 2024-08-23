package net.sharksystem.pki;

import net.sharksystem.SharkException;
import net.sharksystem.SharkTestPeerFS;
import net.sharksystem.SharkUnknownBehaviourException;
import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.persons.PersonValues;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.crypto.ASAPCryptoAlgorithms;
import net.sharksystem.fs.FSUtils;
import net.sharksystem.testhelper.SharkPKITesthelper;
import net.sharksystem.utils.Log;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Collection;

import static net.sharksystem.asap.persons.PersonValues.DEFAULT_SIGNING_FAILURE_RATE;
import static net.sharksystem.pki.TestConstants.*;
import static net.sharksystem.pki.TestHelper.*;

public class SharkComponentUsageTests {
    private class CredentialListenerExample implements SharkCredentialReceivedListener {
        private final SharkPKIComponent sharkPKIComponent;
        public int numberOfEncounter = 0;
        public CredentialMessage lastCredentialMessage;

        public CredentialListenerExample(SharkPKIComponent sharkPKIComponent) {
            this.sharkPKIComponent = sharkPKIComponent;
        }

        @Override
        public void credentialReceived(CredentialMessage credentialMessage) {
            Log.writeLog(this, this.sharkPKIComponent.getOwnerID(), "credential received:\n"
                    + PKIHelper.credentialMessage2String(credentialMessage));
            try {
                /*
                Absolutely not. No! Automatically signing a credential message which simply came along from an unknown
                source is ridiculous. Never ever write an app like this. That's only for debugging. Only!
                Don't even think things like: "Em, well, I just take is for a temporary solution, just to
                illustrate that it works..." It works, alright. That is what this test is for.

                Taking it as 'temporary' solution is most probably BS and you know that. Deal with security from the
                beginning of your app development. Security is not anything you add 'sometimes later'. It is
                part of your app philosophy or not.
                You will make the world a better place by embracing security. :)

                It is important: Users must ensure correct data. Human users must ensure that those data are valid and
                the sending person is really who s/he claims to be.
                 */
                this.numberOfEncounter++;
                this.lastCredentialMessage = credentialMessage;
                Log.writeLog(this, this.sharkPKIComponent.getOwnerID(), ">>>>>>>>>> DO THE UNDOABLE - ISSUE CERTIFICATE WITHOUT CHECKING USER IDENTITY");
                Log.writeLog(this, this.sharkPKIComponent.getOwnerID(), "going to issue a certificate");
                this.sharkPKIComponent.acceptAndSignCredential(credentialMessage);
            } catch (IOException | ASAPSecurityException e) {
                e.printStackTrace();
            }
        }
    }

    SharkTestPeerFS aliceSharkPeer, bobSharkPeer;
    SharkPKIComponentImpl aliceComponent, bobComponent;

    private void setUpAndStartAliceAndBob() throws SharkException, InterruptedException {
        ////////////////////////////////////////// ALICE /////////////////////////////////////////////////////////
        /* it is a test - we use the test peer implementation
         only use SharkPeer interface in your application and create a SharkPeerFS instance
         That's for testing only
         */
        SharkPKITesthelper.incrementTestNumber();
        String folderName = SharkPKITesthelper.getPKITestFolder(ROOT_DIRECTORY);
        System.out.println("folderName == " + folderName);

        ///////// Alice
        aliceSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(ALICE_NAME, folderName);
        aliceComponent =
                (SharkPKIComponentImpl) SharkPKITesthelper.setupPKIComponentPeerNotStarted(aliceSharkPeer, ALICE_ID);
        aliceSharkPeer.start(ALICE_ID);

        ////////////////////////////////////////// BOB ///////////////////////////////////////////////////////////
        bobSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(BOB_NAME, folderName);
        bobComponent = (SharkPKIComponentImpl)
                SharkPKITesthelper.setupPKIComponentPeerNotStarted(bobSharkPeer, BOB_ID);
        bobSharkPeer.start(BOB_ID);

        Thread.sleep(200);
    }

    /**
     * Alice sends her credential to Bob.
     * @throws SharkException
     * @throws ASAPException
     * @throws IOException
     * @throws InterruptedException
     * @throws SharkUnknownBehaviourException
     */
    @Test
    public void sendCredentialMessageExplicitAndExpectSignedCertificate() throws SharkException, ASAPException,
            IOException, InterruptedException, SharkUnknownBehaviourException {

        this.setUpAndStartAliceAndBob();
        System.out.println("testNumber == " + SharkPKITesthelper.testNumber);


        // do not send credential message whenever a new peer is encountered
        aliceComponent.setBehaviour(SharkPKIComponent.BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER, false);
        bobComponent.setBehaviour(SharkPKIComponent.BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER, false);

        /* Bob will not ask for a certificate but would issue but set a listener
         * usually - peers should do both - send and sign. This example splits those to parts for illustration
         * and testing purposes
         */
        bobComponent.setSharkCredentialReceivedListener(new CredentialListenerExample(bobComponent));

        ///////////////////////////////// Encounter Alice - Bob ////////////////////////////////////////////////////
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> start encounter >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(getPortNumber(), bobSharkPeer.getASAPTestPeerFS());
        Thread.sleep(200);

        aliceComponent.sendTransientCredentialMessage();
        Thread.sleep(200);

        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(bobSharkPeer.getASAPTestPeerFS());
        System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< stop encounter <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");

        ////// expectations... Bob signed the credentials and created a certificate which ended up at alice side
        // more tests in sendReceiveCredentialSignAndAddNewCertificate

        // some more usage examples
        Collection<ASAPCertificate> certificatesByIssuer = aliceComponent.getCertificatesByIssuer(BOB_ID);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        PersonValues alicePersonValues = bobComponent.getPersonValuesByID(ALICE_ID);
        Assert.assertNotNull(alicePersonValues);
        Assert.assertEquals(alicePersonValues.getSigningFailureRate(), DEFAULT_SIGNING_FAILURE_RATE);

    }

    /**
     * Alice send her credential information to Bob and expects him to sign. Certificates issued by Bob must be
     * available on both sides.
     * <p>
     * Problems / Bugs:
     * credential is sent twice from Alice to Bob - it wrong but less important - Bob should deal with it.
     *
     * @throws SharkException
     * @throws ASAPSecurityException
     * @throws IOException
     * @throws InterruptedException
     */
    @Test
    public void sendReceiveCredentialSignAndAddNewCertificate() throws SharkException, ASAPException,
            IOException, InterruptedException, SharkUnknownBehaviourException {
        this.setUpAndStartAliceAndBob();
        System.out.println("testNumber == " + SharkPKITesthelper.testNumber);


        // send credential message whenever a new peer is encountered - would not sign one (there is no listener)
        aliceComponent.setBehaviour(SharkPKIComponent.BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER, true);
        bobComponent.setBehaviour(SharkPKIComponent.BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER, true);

        /* Bob will not ask for a certificate but would issue but set a listener
         * usually - peers should do both - send and sign. This example splits those to parts for illustration
         * and testing purposes
         */
        bobComponent.setSharkCredentialReceivedListener(new CredentialListenerExample(bobComponent));

        ///////////////////////////////// Encounter Alice - Bob ////////////////////////////////////////////////////
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> start encounter >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(getPortNumber(), bobSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(500);
        //Thread.sleep(Long.MAX_VALUE);
        System.out.println("slept a moment");
        /////////////////////////////////////////// Tests  /////////////////////////////////////////////////////////

        /* What happened:
        a) Alice and Bob sent credential messages; because: default behaviour: sent credential if we do not have yet a
        certificate issued by a peer we met
        b) Only Bob has a registered credential received listener in place. It creates a certificate and sends it back.
        c) as a result: There is a certificate for subject Alice issued by Bob
         */

        // Bob must have a certificate of Alice - he issued it by himself
        Collection<ASAPCertificate> certificatesByIssuer = bobComponent.getCertificatesByIssuer(BOB_ID);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        // Alice must have got one too - issued by Bob and automatically transmitted by certificate component
        certificatesByIssuer = aliceComponent.getCertificatesByIssuer(BOB_ID);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(bobSharkPeer.getASAPTestPeerFS());
        // further tests after loosing connection
        // non yet

        // some more usage examples
        ASAPCertificate oneCertificate = aliceComponent.getCertificateByIssuerAndSubject(BOB_ID, ALICE_ID);
        Collection<ASAPCertificate> collectionOfCerts = aliceComponent.getCertificatesByIssuer(BOB_ID);
        collectionOfCerts = aliceComponent.getCertificatesBySubject(ALICE_ID);

        ///////////////////////////////////////////// signing: Alice -> Bob
        byte[] message = "From Alice and signed".getBytes();
        byte[] signedMessage = ASAPCryptoAlgorithms.sign(message, aliceComponent);

        boolean verified = ASAPCryptoAlgorithms.verify(message, signedMessage, ALICE_ID, bobComponent);

        String messageString = "From Alice, encrypted for Bob";
        // produce bytes
        byte[] messageBytes = messageString.getBytes();

        ///////////////////////////////////////////// encryption: Bob -> Alice
        // produce encryption package: encrypt with new session key, encrypt session key with receivers public key
        byte[] encryptedMessagePackageBytes = ASAPCryptoAlgorithms.produceEncryptedMessagePackage(
                messageBytes, // message that is encrypted
                ALICE_ID, // recipient id
                bobComponent // key store sender
        );

        // package is sent e.g. with ASAP
        byte[] receivedEncryptedPackageBytes = encryptedMessagePackageBytes;

        // receiver creates package from byte[] - will fail if we are not recipient
        ASAPCryptoAlgorithms.EncryptedMessagePackage receivedEncryptedPackage =
                ASAPCryptoAlgorithms.parseEncryptedMessagePackage(receivedEncryptedPackageBytes);

        // decrypt message
        byte[] receivedMessageBytes =
                ASAPCryptoAlgorithms.decryptPackage(receivedEncryptedPackage, aliceComponent);

        // must be the same
        Assert.assertArrayEquals(messageBytes, receivedMessageBytes);
    }

    /**
     * If set, a component would send a credential message during encounter. This message is changed if a
     * new key pair ist set. Only one message is sent. Old credential messages are removed.
     */
    @Test
    public void sendCredentialMessageDuringEncounterAndChangeItWithNewKeyPair() throws SharkException, ASAPException,
            IOException, InterruptedException, SharkUnknownBehaviourException {
        ////////////////////////////////////////// ALICE /////////////////////////////////////////////////////////
        /* it is a test - we use the test peer implementation
         only use SharkPeer interface in your application and create a SharkPeerFS instance
         That's for testing only
         */
//        SharkTestPeerFS aliceSharkPeer = new SharkTestPeerFS(ALICE_NAME, ALICE_FOLDER);
//        SharkPKIComponent aliceComponent = this.setupComponent(ALICE_ID, aliceSharkPeer);

        SharkPKITesthelper.incrementTestNumber();
        System.out.println("testNumber == " + SharkPKITesthelper.testNumber);
        String folderName = SharkPKITesthelper.getPKITestFolder(ROOT_DIRECTORY);
        System.out.println("folderName == " + folderName);

        SharkTestPeerFS aliceSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(ALICE_NAME, folderName);
        SharkPKIComponent aliceComponent = SharkPKITesthelper.setupPKIComponentPeerNotStarted(aliceSharkPeer, ALICE_ID);

        // lets starts peer and its components before doing anything else
        aliceSharkPeer.start(ALICE_ID);

        // send credential message whenever a new peer is encountered - would not sign one (there is no listener)
        aliceComponent.setBehaviour(SharkPKIComponent.BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER, true);

        ////////////////////////////////////////// BOB ///////////////////////////////////////////////////////////

        SharkTestPeerFS bobSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(BOB_NAME, folderName);
        SharkPKIComponent bobComponent = SharkPKITesthelper.setupPKIComponentPeerNotStarted(bobSharkPeer, BOB_ID);

        // lets starts peer and its components before doing anything else
        bobSharkPeer.start(BOB_ID);

        /* Bob will not ask for a certificate but would issue on - set a listener
         * usually - peers should do both - send and sign. This example splits those to parts for illustration
         * and testing purposes
         */
        CredentialListenerExample bobCredentialListener = new CredentialListenerExample(bobComponent);
        bobComponent.setSharkCredentialReceivedListener(bobCredentialListener);

        ///////////////////////////////// Encounter #1 Alice - Bob ////////////////////////////////////////////////////
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>> start encounter Alice - Bob >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(getPortNumber(), bobSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(200);
        //Thread.sleep(Long.MAX_VALUE);
        System.out.println("slept a moment");
        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(bobSharkPeer.getASAPTestPeerFS());

        Assert.assertEquals(1, bobCredentialListener.numberOfEncounter);

        // remember credential message
        CredentialMessage firstBobCredential = bobCredentialListener.lastCredentialMessage;

        /////////////////////////////////////////// Alice changes keypair /////////////////////////////////////////////
        aliceComponent.generateKeyPair();
        //Thread.sleep(Long.MAX_VALUE);

        ///////////////////////////////// Encounter #2 Alice - Bob ////////////////////////////////////////////////////
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> start encounter Alice - Bob #2 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(getPortNumber(), bobSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(200);
        //Thread.sleep(Long.MAX_VALUE);
        System.out.println("slept a moment");
        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(bobSharkPeer.getASAPTestPeerFS());
        Assert.assertEquals(2, bobCredentialListener.numberOfEncounter);

        // remember credential message
        CredentialMessage secondBobCredential = bobCredentialListener.lastCredentialMessage;

        // both are different
        Assert.assertNotEquals(firstBobCredential.getValidSince(), secondBobCredential.getValidSince());

        ////////////////////////////////////////// CLARA ///////////////////////////////////////////////////////////
        SharkTestPeerFS.removeFolder(CLARA_FOLDER);
        SharkTestPeerFS claraSharkPeer = new SharkTestPeerFS(CLARA_NAME, CLARA_FOLDER);
        SharkPKIComponent claraComponent = this.setupComponent(CLARA_ID, claraSharkPeer);

        // lets starts peer and its components before doing anything else
        claraSharkPeer.start(CLARA_ID);
        CredentialListenerExample claraCredentialListener = new CredentialListenerExample(claraComponent);
        claraComponent.setSharkCredentialReceivedListener(claraCredentialListener);

        ///////////////////////////////// Encounter #3 Alice - Clara ////////////////////////////////////////////////////
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>> start encounter Alice - Clara >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(getPortNumber(), claraSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(200);
        //Thread.sleep(Long.MAX_VALUE);
        System.out.println("slept a moment");
        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(claraSharkPeer.getASAPTestPeerFS());

        Assert.assertEquals(1, claraCredentialListener.numberOfEncounter);

        // remember credential message
        CredentialMessage firstClaraCredential = claraCredentialListener.lastCredentialMessage;

        // bob and claras last received credentials are the same
        Assert.assertEquals(firstClaraCredential.getValidSince(), secondBobCredential.getValidSince());
    }

    private SharkPKIComponent setupComponent(String peerID, SharkTestPeerFS sharkPeer) throws SharkException {
        return SharkPKITesthelper.setupPKIComponentPeerNotStarted(sharkPeer, peerID);
    }

    /**
     * This test runs without actual ASAP communication but using getter und setter of certificates.
     * <br/><br/>
     * Alice and Bob generate a credential messages. Both messages are acceptedAndSigned -> two certificates
     * are created: Alice issues one for Bob and signs it and vice versa. Now, Bob does the same with Clara.
     * <br/><br/>
     * Finally, certificate issued by Bob for Alice is added to Clara's PKI.
     * <br/><br/>
     * Check identity assurance for each relation A-B (10 | 10), B-C (10 | 10) and A-C (0 | 90)
     *
     * @throws SharkException
     * @throws ASAPException
     * @throws IOException
     * @throws InterruptedException
     */
    @Test
    public void testIdentityAssurance() throws SharkException, ASAPException,
            IOException, InterruptedException {
        ////////////////////////////////////////// ALICE /////////////////////////////////////////////////////////
        /* it is a test - we use the test peer implementation
         only use SharkPeer interface in your application and create a SharkPeerFS instance
         That's for testing only
         */
        SharkPKITesthelper.incrementTestNumber();
        System.out.println("testNumber == " + SharkPKITesthelper.testNumber);

        String folderName = SharkPKITesthelper.getPKITestFolder(ROOT_DIRECTORY);
        System.out.println("folderName == " + folderName);

        SharkTestPeerFS aliceSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(ALICE_NAME, folderName);
        SharkPKIComponent alicePKI = SharkPKITesthelper.setupPKIComponentPeerNotStarted(aliceSharkPeer, ALICE_ID);
        // lets starts peer and its components before doing anything else
        aliceSharkPeer.start(ALICE_ID);

        SharkTestPeerFS bobSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(BOB_NAME, folderName);
        SharkPKIComponent bobPKI = SharkPKITesthelper.setupPKIComponentPeerNotStarted(bobSharkPeer, BOB_ID);
        // lets starts peer and its components before doing anything else
        bobSharkPeer.start(BOB_ID);

        SharkTestPeerFS claraSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(CLARA_NAME, folderName);
        SharkPKIComponent claraPKI = SharkPKITesthelper.setupPKIComponentPeerNotStarted(claraSharkPeer, CLARA_ID);
        // lets starts peer and its components before doing anything else
        claraSharkPeer.start(CLARA_ID);

        CredentialMessage aliceCredentialMessage = alicePKI.createCredentialMessage(LOST_BYTES);
        CredentialMessage bobCredentialMessage = bobPKI.createCredentialMessage();

        // Alice and Bob exchange and accept credential messages and issue certificates
        ASAPCertificate aliceIssuedBobCert = alicePKI.acceptAndSignCredential(bobCredentialMessage);
        ASAPCertificate bobIssuedAliceCert = bobPKI.acceptAndSignCredential(aliceCredentialMessage);

        // Bob and Clara meet, accept credential messages and issue certificates
        CredentialMessage claraCredentialMessage = claraPKI.createCredentialMessage();
        ASAPCertificate claraIssuedBobCert = claraPKI.acceptAndSignCredential(bobCredentialMessage);
        ASAPCertificate bobIssuedClaraCert = bobPKI.acceptAndSignCredential(claraCredentialMessage);

        // Clara gets Bob issued cert for Alice
        claraPKI.addCertificate(bobIssuedAliceCert);

        // check identity assurance
        int iaAliceSideBob = alicePKI.getIdentityAssurance(bobSharkPeer.getPeerID());
        int iaAliceSideClara = alicePKI.getIdentityAssurance(claraSharkPeer.getPeerID());

        int iaBobSideAlice = bobPKI.getIdentityAssurance(aliceSharkPeer.getPeerID());
        int iaBobSideClara = bobPKI.getIdentityAssurance(claraSharkPeer.getPeerID());

        int iaClaraSideAlice = claraPKI.getIdentityAssurance(aliceSharkPeer.getPeerID());
        int iaClaraSideBob = claraPKI.getIdentityAssurance(bobSharkPeer.getPeerID());

        Assert.assertEquals(10, iaAliceSideBob); // met
        System.out.println("10 - okay, Alice met Bob");
        Assert.assertEquals(0, iaAliceSideClara); // never seen, no certificate on Alice side
        System.out.println("0 - okay, Alice knows nothing about Clara");
        Assert.assertEquals(10, iaBobSideAlice); // met
        System.out.println("10 - okay, Bob met Alice");
        Assert.assertEquals(10, iaBobSideClara); // met
        System.out.println("10 - okay, Bob met Clara");
        Assert.assertEquals(5, iaClaraSideAlice); // got certificate from Bob, with default failure rate == 5
        System.out.println("5 - okay, Clara has got a certificate issued by Bob (with failure rate 5)");
        Assert.assertEquals(10, iaClaraSideBob); // met
        System.out.println("10 - okay, Clara met Bob");

        // change failure rate
        claraPKI.setSigningFailureRate(bobSharkPeer.getPeerID(), 1); // best failure rate
        iaClaraSideAlice = claraPKI.getIdentityAssurance(aliceSharkPeer.getPeerID()); // get again
        Assert.assertEquals(9, iaClaraSideAlice); // must be better now
        System.out.println("9 - okay, Clara has got a certificate issued by Bob (better failure rate (9) now)");
    }
}