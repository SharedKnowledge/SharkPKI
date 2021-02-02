package net.sharksystem;

import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPCertificate;
import net.sharksystem.asap.crypto.ASAPCryptoAlgorithms;
import net.sharksystem.asap.persons.CredentialMessage;
import net.sharksystem.utils.Log;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Collection;

import static net.sharksystem.TestConstants.*;

public class SharkComponentUsageTests {
    public static final String SPECIFIC_ROOT_FOLDER = ROOT_DIRECTORY + "sharkComponentTests/";
    public static final String ALICE_FOLDER = SPECIFIC_ROOT_FOLDER + ALICE_NAME;
    public static final String BOB_FOLDER = SPECIFIC_ROOT_FOLDER + BOB_NAME;
    public static final String CLARA_FOLDER = SPECIFIC_ROOT_FOLDER + CLARA_NAME;

    private SharkCertificateComponent setupComponent(SharkPeer sharkPeer)
            throws SharkException, ASAPSecurityException {

        // create a component factory
        SharkCertificateComponentFactory certificateComponentFactory = new SharkCertificateComponentFactory();

        // register this component with shark peer - note: we use interface SharkPeer
        sharkPeer.addComponent(certificateComponentFactory, SharkCertificateComponent.class);

        // get component instance
        SharkComponent component = sharkPeer.getComponent(SharkCertificateComponent.class);

        // project "clean code" :) we only use interfaces - unfortunately casting is unavoidable
        SharkCertificateComponent sharkCertificateComponent = (SharkCertificateComponent) component;

        return sharkCertificateComponent;
    }

    /**
     * ALice send her credential information to Bob and expects him to sign. Certificates issued by Bob must be
     * available on both sides.
     *
     * Problems / Bugs:
     * credential is sent twice from Alice to Bob - it wrong but less important - Bob should deal it.
     *
     * @throws SharkException
     * @throws ASAPSecurityException
     * @throws IOException
     * @throws InterruptedException
     */
    @Test
    public void sendReceiveCredentialSignAndAddNewCertificate() throws SharkException, ASAPException,
            IOException, InterruptedException {
        ////////////////////////////////////////// ALICE /////////////////////////////////////////////////////////
        /* it is a test - we use the test peer implementation
         only use SharkPeer interface in your application and create a SharkPeerFS instance
         That's for testing only
         */
        SharkTestPeerFS.removeFolder(ROOT_DIRECTORY);
        SharkTestPeerFS aliceSharkPeer = new SharkTestPeerFS(ALICE_NAME, ALICE_FOLDER);

        SharkCertificateComponent aliceComponent = this.setupComponent(aliceSharkPeer);

        // lets starts peer and its components before doing anythings else
        aliceSharkPeer.start();

        // send credential message whenever a new peer is encountered - would not sign one (there is no listener)
        aliceComponent.setBehaviour(SharkCertificateComponent.SEND_CREDENTIAL_FIRST_ENCOUNTER, true);

        ////////////////////////////////////////// BOB ///////////////////////////////////////////////////////////
        SharkTestPeerFS.removeFolder(BOB_FOLDER);
        SharkTestPeerFS bobSharkPeer = new SharkTestPeerFS(BOB_NAME, BOB_FOLDER);
        SharkCertificateComponent bobComponent = this.setupComponent(bobSharkPeer);

        // lets starts peer and its components before doing anythings else
        bobSharkPeer.start();

        /* Bob will not ask for a certificate but would issue on - set a listener
         * usually - peers should do both - send and sign. This example splits those to parts for illustration
         * and testing purposes
         */
        bobComponent.setSharkCredentialReceivedListener(new CredentialListenerExample(bobComponent));

        ///////////////////////////////// Encounter Alice - Bob ////////////////////////////////////////////////////
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> start encounter >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(7777, bobSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(1000);
        //Thread.sleep(Long.MAX_VALUE);
        System.out.println("slept a moment");

        /////////////////////////////////////////// Tests  /////////////////////////////////////////////////////////

        // Bob must have a certificate of Alice - he issued it by himself
        Collection<ASAPCertificate> certificatesByIssuer = bobComponent.getCertificatesByIssuer(BOB_NAME);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        // Alice must have got one too - issued by Bob and automatically transmitted by certificate component
        certificatesByIssuer = aliceComponent.getCertificatesByIssuer(BOB_NAME);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(bobSharkPeer.getASAPTestPeerFS());
        // further tests after loosing connection
        // non yet

        // some more usage examples
        ASAPCertificate oneCertificate = aliceComponent.getCertificateByIssuerAndSubject(BOB_NAME, ALICE_NAME);
        Collection<ASAPCertificate> collectionOfCerts = aliceComponent.getCertificatesByIssuer(BOB_NAME);
        collectionOfCerts = aliceComponent.getCertificatesBySubject(ALICE_NAME);

        ///////////////////////////////////////////// signing: Alice -> Bob
        byte[] message = "From Alice and signed".getBytes();
        byte[] signedMessage = ASAPCryptoAlgorithms.sign(message, aliceComponent);

        boolean verified = ASAPCryptoAlgorithms.verify(message, signedMessage, ALICE_NAME, bobComponent);

        String messageString = "From Alice, encrypted for Bob";
        // produce bytes
        byte[] messageBytes = messageString.getBytes();

        ///////////////////////////////////////////// encryption: Bob -> Alice
        // produce encryption package: encrypt with new session key, encrypt session key with receivers public key
        byte[] encryptedMessagePackageBytes = ASAPCryptoAlgorithms.produceEncryptedMessagePackage(
                messageBytes, // message that is encrypted
                ALICE_NAME, // recipient id
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

    private class CredentialListenerExample implements SharkCredentialReceivedListener {
        private final SharkCertificateComponent sharkCertificateComponent;

        public CredentialListenerExample(SharkCertificateComponent sharkCertificateComponent) {
            this.sharkCertificateComponent = sharkCertificateComponent;
        }

        @Override
        public void credentialReceived(CredentialMessage credentialMessage) {
            try {
                /*
                Absolutely not. No! Automatically signing a credential message which simply came along from an unknown
                source is ridiculous. Never ever write an app like this. That's only for debugging. Only!
                Don't even think things like: "Em, well, I just take is for a temporary solution, just to
                illustrate that it works..." It works, alright. That is what this test is for.

                Taking it as 'temporary' solution is most probably BS and you know that. Deal with security from the
                beginning of your app development. Security is not anything you add 'sometimes later'. It is
                part of your apps philosophy or it is not.
                You will make the world a better place by embracing security. :)

                It is important: Users must ensure correct data. Human users must ensure that those data are valid and
                the sending person is really who their claims their is
                 */
                Log.writeLog(this, "going to issue a certificate");
                this.sharkCertificateComponent.acceptAndSignCredential(credentialMessage);
            } catch (IOException | ASAPSecurityException e) {
                e.printStackTrace();
            }

        }
    }
}
