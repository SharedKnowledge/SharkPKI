package net.sharksystem;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPCertificate;
import net.sharksystem.asap.persons.CredentialMessage;
import net.sharksystem.utils.Log;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Collection;

public class SharkComponentUsageTests {
    public static final String ROOT_FOLDER = "asapCertificateComponentFolder";
    public static final String ALICE = "Alice";
    public static final String ALICE_FOLDER = ROOT_FOLDER + "/" + ALICE;
    public static final String BOB = "Bob";
    public static final String BOB_FOLDER = ROOT_FOLDER + "/" + BOB;
    public static final String CALIANA = "Caliana";
    public static final String CALIANA_FOLDER = ROOT_FOLDER + "/" + CALIANA;

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

    @Test
    public void sendReceiveCredentialSignAndAddNewCertificate() throws SharkException, ASAPSecurityException,
            IOException, InterruptedException {
        ////////////////////////////////////////// ALICE /////////////////////////////////////////////////////////
        /* it is a test - we use the test peer implementation
         only use SharkPeer interface in your application and create a SharkPeerFS instance
         That's for testing only
         */
        SharkTestPeerFS.removeFolder(ALICE_FOLDER);
        SharkTestPeerFS aliceSharkPeer = new SharkTestPeerFS(ALICE, ALICE_FOLDER);

        SharkCertificateComponent aliceComponent = this.setupComponent(aliceSharkPeer);

        // lets starts peer and its components before doing anythings else
        aliceSharkPeer.start();

        //  create a new key pair - this will hold for at least a year long enough for this test
        aliceComponent.generateKeyPair();

        // send credential message whenever a new peer is encountered - would not sign one (there is no listener)
        aliceComponent.setBehaviour(SharkCertificateComponent.SEND_CREDENTIAL_FIRST_ENCOUNTER, true);

        ////////////////////////////////////////// BOB ///////////////////////////////////////////////////////////
        SharkTestPeerFS.removeFolder(BOB_FOLDER);
        SharkTestPeerFS bobSharkPeer = new SharkTestPeerFS(BOB, BOB_FOLDER);
        SharkCertificateComponent bobComponent = this.setupComponent(bobSharkPeer);

        // lets starts peer and its components before doing anythings else
        bobSharkPeer.start();

        //  create a new key pair - this will hold for at least a year long enough for this test
        bobComponent.generateKeyPair();

        /* Bob will not ask for a certificate but would issue on - set a listener
         * usually - peers should do both - send and sign. This example splits those to parts for illustration
         * and testing purposes
         */
        bobComponent.setSharkCredentialReceivedListener(new CredentialListenerExample(bobComponent));

        ///////////////////////////////// Encounter Alice - Bob ////////////////////////////////////////////////////
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(7777, bobSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(1000);

        /////////////////////////////////////////// Tests  /////////////////////////////////////////////////////////

        // Bob must have a certificate of Alice - he issued it by himself
        Collection<ASAPCertificate> certificatesByIssuer = bobComponent.getCertificatesByIssuer(BOB);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        // Alice must have got one too - issued by Bob and automatically transmitted by certificate component
        certificatesByIssuer = aliceComponent.getCertificatesByIssuer(BOB);
        Assert.assertNotNull(certificatesByIssuer);
        Assert.assertEquals(1, certificatesByIssuer.size());

        int i = 42; // debug break
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
                Absolutely no. No! Automatically signing a credential message which simply came along from an unknown
                source is ridiculous. Never ever write an app like this. That's only for debugging. Only!
                Don't even think things like: "Em, well, I just take is for a temporary solution, just to
                illustrate that it works..." It works, alright. That is this test for.

                Taking it as 'temporary' solution is most probably BS and you know that. Deal with security from the
                beginning of your app development. Security is not anything you add 'sometimes later'. It is
                part of your apps philosophy or it is not.
                You will make the world a better place by embracing security. :)

                It is important: Users must ensure correct data. Human users must ensure that those data are valid and
                the sending person is really who their claims their is
                 */
                Log.writeLog(this, credentialMessage.toString());
                this.sharkCertificateComponent.acceptAndSignCredential(credentialMessage);
            } catch (IOException | ASAPSecurityException e) {
                e.printStackTrace();
            }

        }
    }
}
