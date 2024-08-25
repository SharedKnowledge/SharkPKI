package net.sharksystem.pki;

import net.sharksystem.SharkException;
import net.sharksystem.SharkPeer;
import net.sharksystem.SharkTestPeerFS;
import net.sharksystem.asap.persons.PersonValues;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.testhelper.ASAPTesthelper;
import net.sharksystem.testhelper.SharkPKITesthelper;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;

import static net.sharksystem.testhelper.ASAPTesthelper.*;

public class IntegrationsTestsFromFacade {
    @Test
    public void testPersistence() throws SharkException, IOException {
        SharkPKITesthelper.incrementTestNumber();
        String folderName = SharkPKITesthelper.getPKITestFolder(ASAPTesthelper.ROOT_DIRECTORY_TESTS);

        // ALICE
        SharkPeer aliceSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(ALICE_NAME, folderName);
        SharkPKIComponentImpl alicePKIBackdoor = (SharkPKIComponentImpl)
                new SharkPKIComponentFactory().getComponent(aliceSharkPeer);
        SharkPKIComponent alicePKI = alicePKIBackdoor;

        // BOB
        SharkPeer bobSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(BOB_NAME, folderName);
        SharkPKIComponentImpl bobPKIBackdoor = new SharkPKIComponentImpl(bobSharkPeer);
        SharkPKIComponent bobPKI = bobPKIBackdoor;

        // CLARA
        SharkPeer claraSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(CLARA_NAME, folderName);
        SharkPKIComponentImpl claraPKIBackdoor = new SharkPKIComponentImpl(claraSharkPeer);
        SharkPKIComponent claraPKI = claraPKIBackdoor;

        // init all systems
        aliceSharkPeer.start(ALICE_ID);
        bobSharkPeer.start(BOB_ID);
        claraSharkPeer.start(CLARA_ID);
        alicePKI.onStart(aliceSharkPeer.getASAPPeer());
        bobPKI.onStart(bobSharkPeer.getASAPPeer());
        claraPKI.onStart(claraSharkPeer.getASAPPeer());

        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println("++                         systems are running                            ++");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");

        ///////////// fill alice with some certificates
        CredentialMessage bobCredentialMessage = bobPKIBackdoor.getASAPPKIStorage().createCredentialMessage();
        CredentialMessage claraCredentialMessage = claraPKIBackdoor.getASAPPKIStorage().createCredentialMessage();

        alicePKI.acceptAndSignCredential(bobCredentialMessage);
        alicePKI.acceptAndSignCredential(claraCredentialMessage);

        // now alice issued certificates for bob and clara
        Collection<ASAPCertificate> aliceIssuedCertificates = alicePKI.getCertificatesByIssuer(ALICE_ID);
        Assert.assertEquals(2, aliceIssuedCertificates.size());
        Collection<ASAPCertificate> aliceIssuedForBob = alicePKI.getCertificatesBySubject(BOB_ID);
        Assert.assertEquals(1, aliceIssuedForBob.size());
        Collection<ASAPCertificate> aliceIssuedForClara = alicePKI.getCertificatesBySubject(CLARA_ID);
        Assert.assertEquals(1, aliceIssuedForClara.size());

        // alice should also know both of them
        PersonValues alicePersonValuesOfBob = alicePKI.getPersonValuesByID(BOB_ID);
        Assert.assertNotNull(alicePersonValuesOfBob);
        PersonValues alicePersonValuesOfClara = alicePKI.getPersonValuesByID(CLARA_ID);
        Assert.assertNotNull(alicePersonValuesOfClara);

        // we should get a public key from both of them
        PublicKey publicKeyBob = alicePKIBackdoor.getASAPPKIStorage().getPublicKey(BOB_ID);
        Assert.assertNotNull(publicKeyBob);
        PublicKey publicKeyClara = alicePKIBackdoor.getASAPPKIStorage().getPublicKey(CLARA_ID);
        Assert.assertNotNull(publicKeyClara);

        // kill alice and ...
        aliceSharkPeer.stop(); aliceSharkPeer = null; alicePKI = null; alicePKIBackdoor = null;

        // restore alice2
        SharkPeer aliceSharkPeer2 = SharkPKITesthelper.setupSharkPeerDoNotStart(ALICE_NAME, folderName);
        SharkPKIComponentImpl alicePKIBackdoor2 = new SharkPKIComponentImpl(aliceSharkPeer2);
        SharkPKIComponent alicePKI2 = alicePKIBackdoor2;
        aliceSharkPeer2.start(ALICE_ID);
        alicePKI2.onStart(aliceSharkPeer2.getASAPPeer());

        // alice should remember
        aliceIssuedCertificates = alicePKI2.getCertificatesByIssuer(ALICE_ID);
        Assert.assertEquals(2, aliceIssuedCertificates.size());
        aliceIssuedForBob = alicePKI2.getCertificatesBySubject(BOB_ID);
        Assert.assertEquals(1, aliceIssuedForBob.size());
        aliceIssuedForClara = alicePKI2.getCertificatesBySubject(CLARA_ID);
        Assert.assertEquals(1, aliceIssuedForClara.size());

        // alice should also know both of them
        alicePersonValuesOfBob = alicePKI2.getPersonValuesByID(BOB_ID);
        Assert.assertNotNull(alicePersonValuesOfBob);
        alicePersonValuesOfClara = alicePKI2.getPersonValuesByID(CLARA_ID);
        Assert.assertNotNull(alicePersonValuesOfClara);

        publicKeyBob = alicePKIBackdoor2.getASAPPKIStorage().getPublicKey(BOB_ID);
        Assert.assertNotNull(publicKeyBob);
        publicKeyClara = alicePKIBackdoor2.getASAPPKIStorage().getPublicKey(CLARA_ID);
        Assert.assertNotNull(publicKeyClara);

        /*
        keyStore.setMementoTarget(this.appSettings, KEYSTORE_MEMENTO_KEY);
        try {
            keyStore.restoreFromMemento(this.appSettings.getExtra(KEYSTORE_MEMENTO_KEY));
            this.tellUI("restored keystore from memento");
        }
        catch(SharkException se) {
            // no memento for key store - must be new
            this.tellUI("no keystore memento - must be new");
        }
         */
    }

    @Test
    public void testIAWithRoutedMessages() throws SharkException, IOException, InterruptedException {
        SharkPKITesthelper.incrementTestNumber();
        String folderName = SharkPKITesthelper.getPKITestFolder(ASAPTesthelper.ROOT_DIRECTORY_TESTS);
        System.out.println("ASSUMED: TEST 'testPersistence' WORKS");

        // ALICE
        SharkTestPeerFS aliceSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(ALICE_NAME, folderName);
        SharkPKIComponentImpl alicePKIBackdoor = (SharkPKIComponentImpl)
                new SharkPKIComponentFactory().getComponent(aliceSharkPeer);
        SharkPKIComponent alicePKI = alicePKIBackdoor;

        // BOB
        SharkTestPeerFS bobSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(BOB_NAME, folderName);
        SharkPKIComponentImpl bobPKIBackdoor = new SharkPKIComponentImpl(bobSharkPeer);
        SharkPKIComponent bobPKI = bobPKIBackdoor;

        // CLARA
        SharkTestPeerFS claraSharkPeer = SharkPKITesthelper.setupSharkPeerDoNotStart(CLARA_NAME, folderName);
        SharkPKIComponentImpl claraPKIBackdoor = new SharkPKIComponentImpl(claraSharkPeer);
        SharkPKIComponent claraPKI = claraPKIBackdoor;

        // start the system
        aliceSharkPeer.start(ALICE_ID);
        bobSharkPeer.start(BOB_ID);
        claraSharkPeer.start(CLARA_ID);

        // tell components
        alicePKI.onStart(aliceSharkPeer.getASAPPeer());
        bobPKI.onStart(bobSharkPeer.getASAPPeer());
        // bob would sign anything
        bobPKI.setSharkCredentialReceivedListener(new CredentialListenerSignsWithoutChecking(bobPKI));
        claraPKI.onStart(claraSharkPeer.getASAPPeer());
        // clara would sign anything
        claraPKI.setSharkCredentialReceivedListener(new CredentialListenerSignsWithoutChecking(claraPKI));

        //// Alice meets Bob; Bob issues a certificate for Alice
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> start encounter Alice - Bob   >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        aliceSharkPeer.getASAPTestPeerFS().startEncounter(ASAPTesthelper.getPortNumber(), bobSharkPeer.getASAPTestPeerFS());

        // give them moment to exchange data
        Thread.sleep(200);

        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>  producing cert(B,A)  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

        alicePKI.sendTransientCredentialMessage();
        Thread.sleep(200);

        Collection<ASAPCertificate> certAt_A_BA = alicePKI.getCertificatesByIssuer(BOB_ID);
        Collection<ASAPCertificate> certAt_B_BA = bobPKI.getCertificatesBySubject(BOB_ID);
        Assert.assertNotNull(certAt_A_BA); Assert.assertNotNull(certAt_B_BA);
        Assert.assertEquals(1, certAt_A_BA.size()); Assert.assertEquals(1, certAt_B_BA.size());

        aliceSharkPeer.getASAPTestPeerFS().stopEncounter(bobSharkPeer.getASAPTestPeerFS());

        //// Bob meets Clara; Clara receives cert(B,A) automatically; she cannot verify Alice
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> start encounter Bob - Clara   >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        bobSharkPeer.getASAPTestPeerFS().startEncounter(ASAPTesthelper.getPortNumber(), claraSharkPeer.getASAPTestPeerFS());

        Thread.sleep(200);
        int claraIA_Alice = claraPKI.getIdentityAssurance(ALICE_ID);
        Assert.assertEquals(0, claraIA_Alice);

        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>  producing cert(C,B)  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

        Thread.sleep(200);
        ////// Clara issues a certificate for Bob
        bobPKI.sendTransientCredentialMessage();
        Thread.sleep(200);
        bobSharkPeer.getASAPTestPeerFS().stopEncounter(claraSharkPeer.getASAPTestPeerFS());
        Thread.sleep(200);

        Assert.assertNotNull(bobPKI.getCertificatesByIssuer(BOB_ID));
        claraIA_Alice = claraPKI.getIdentityAssurance(ALICE_ID);
        Assert.assertEquals(5, claraIA_Alice);

        // finally.. do we have doublets in certs? TODO
    }
}
