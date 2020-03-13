package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPEngine;
import net.sharksystem.asap.ASAPEngineFS;
import net.sharksystem.asap.ASAPException;
import net.sharksystem.crypto.*;
import org.junit.Assert;
import org.junit.Test;
import org.omg.CORBA.SystemException;

import java.io.IOException;
import java.security.*;
import java.util.Collection;

public class PersonsStorageTests {
    private static final String ROOT_DIRECTORY = "asapStorageRootDirectory/";
    private static final String ROOT_DIRECTORY_ALICE = "asapStorageRootDirectory/alice/";
    private static final String ROOT_DIRECTORY_BOB = "asapStorageRootDirectory/bob/";
    private static final String ROOT_DIRECTORY_CLARA = "asapStorageRootDirectory/clara/";
    private static final String ROOT_DIRECTORY_DAVID = "asapStorageRootDirectory/david/";
    private static final CharSequence ALICE_ID = "42";
    private static final CharSequence ALICE_NAME = "Alice";
    private static final CharSequence BOB_ID = "43";
    private static final CharSequence BOB_NAME = "Bob";
    private static final CharSequence CLARA_ID = "44";
    private static final CharSequence CLARA_NAME = "Clara";
    private static final CharSequence DAVID_ID = "45";
    private static final CharSequence DAVID_NAME = "David";

    private void assertCertificateEquals(ASAPCertificate a, ASAPCertificate b) {
        Assert.assertEquals(a.getSignerID(), b.getSignerID());
        Assert.assertEquals(a.getOwnerID(), b.getOwnerID());
        Assert.assertEquals(a.getOwnerName(), b.getOwnerName());
        Assert.assertEquals(a.getSignerName(), b.getSignerName());
    }

    @Test
    public void identityAssuranceCalculationTest() throws
            IOException, ASAPException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, SharkException {

        ASAPEngineFS.removeFolder(ROOT_DIRECTORY);

        long now = System.currentTimeMillis();

        // setup alice
        ASAPEngine aliceASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_ALICE, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPCertificateStorageImpl(aliceASAPStorage, ALICE_ID, ALICE_NAME);
        PersonsStorage alicePersonsStorage = new PersonsStorageImpl(asapAliceCertificateStorage);

        // setup bob
        ASAPEngine bobASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_BOB, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPCertificateStorageImpl(aliceASAPStorage, BOB_ID, BOB_NAME);
        PersonsStorage bobPersonsStorage = new PersonsStorageImpl(asapBobCertificateStorage);

        // simulation - Bob must send its credentials in some way to Alice - assume that happened
        CharSequence bobID = bobPersonsStorage.getOwnerID();
        CharSequence bobName = bobPersonsStorage.getOwnerName();
        PublicKey bobPublicKey = bobPersonsStorage.getPublicKey();

        // alice signs a certificate of bob
        ASAPCertificate asapCertificate = alicePersonsStorage.addAndSignPerson(bobID, bobName, bobPublicKey, now);

        // Alice could (and should) send it back to Bob - not tested here
        byte[] bytes = asapCertificate.asBytes();

        Assert.assertEquals(OtherPerson.HIGHEST_IDENTITY_ASSURANCE_LEVEL,
                alicePersonsStorage.getIdentityAssurance(bobID));

        // create a certificate of David issued by Clara
        // setup Clara
        ASAPEngine claraASAPStorage = ASAPEngineFS.getASAPStorage(
                "Clara", ROOT_DIRECTORY_CLARA, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapClaraCertificateStorage =
                new ASAPCertificateStorageImpl(claraASAPStorage, CLARA_ID, CLARA_NAME);
        PersonsStorage claraPersonsStorage = new PersonsStorageImpl(asapClaraCertificateStorage);

        // setup David
        ASAPEngine davidASAPStorage = ASAPEngineFS.getASAPStorage(
                "Clara", ROOT_DIRECTORY_DAVID, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapDavidCertificateStorage =
                new ASAPCertificateStorageImpl(davidASAPStorage, DAVID_ID, DAVID_NAME);
        PersonsStorage davidPersonsStorage = new PersonsStorageImpl(asapDavidCertificateStorage);

        // clara signs a certificate of david
        CharSequence davidID = davidPersonsStorage.getOwnerID();
        asapCertificate = claraPersonsStorage.addAndSignPerson(
                davidID,
                davidPersonsStorage.getOwnerName(),
                davidPersonsStorage.getPublicKey(), now);

        // add to alice certification storage
        alicePersonsStorage.addCertificate(asapCertificate);

        Collection<ASAPCertificate> davidCerts = alicePersonsStorage.getCertificateByOwner(davidID);
        Assert.assertNotNull(davidCerts);
        Assert.assertEquals(1, davidCerts.size());

        // alice cannot verify clara - there is no safe way to david
        Assert.assertEquals(OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL,
                alicePersonsStorage.getIdentityAssurance(davidID));

        // bob signs a certificate of clara
        CharSequence claraID = claraPersonsStorage.getOwnerID();
        asapCertificate = bobPersonsStorage.addAndSignPerson(
                claraID,
                claraPersonsStorage.getOwnerName(),
                claraPersonsStorage.getPublicKey(), now);

        // add to alice certification storage
        alicePersonsStorage.addCertificate(asapCertificate);

        // alice can verify clara thanks to bob
        int claraIdentityAssurance = alicePersonsStorage.getIdentityAssurance(claraID);
        System.out.println("clara identity assurance on alice side == " + claraIdentityAssurance);
        Assert.assertEquals(5, claraIdentityAssurance);

        // alice can verify david thanks to bob and clara
        int davidIdentityAssurance = alicePersonsStorage.getIdentityAssurance(davidID);
        System.out.println("david identity assurance on alice side == " + davidIdentityAssurance);
        // there is a way from alice to david now - iA is 2.5 rounded up to 3
        Assert.assertEquals(3, alicePersonsStorage.getIdentityAssurance(davidID));
    }

    @Test
    public void certificateVerifyTest1() throws
            IOException, ASAPException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, SharkException {

        ASAPEngineFS.removeFolder(ROOT_DIRECTORY);

        long now = System.currentTimeMillis();

        // setup alice
        ASAPEngine aliceASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_ALICE, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPCertificateStorageImpl(aliceASAPStorage, ALICE_ID, ALICE_NAME);
        PersonsStorage alicePersonsStorage = new PersonsStorageImpl(asapAliceCertificateStorage);

        // setup bob
        ASAPEngine bobASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_BOB, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPCertificateStorageImpl(aliceASAPStorage, BOB_ID, BOB_NAME);
        PersonsStorage bobPersonsStorage = new PersonsStorageImpl(asapBobCertificateStorage);

        // simulation - Bob must send its credentials in some way to Alice - assume that happened
        CharSequence bobID = bobPersonsStorage.getOwnerID();
        CharSequence bobName = bobPersonsStorage.getOwnerName();
        PublicKey bobPublicKey = bobPersonsStorage.getPublicKey();

        PublicKey alicePublicKey = alicePersonsStorage.getPublicKey();
        PrivateKey alicePrivateKey = alicePersonsStorage.getPrivateKey();

        // alice signs a certificate of bob
        ASAPCertificate asapCertificate = ASAPCertificateImpl.produceCertificate(
                alicePersonsStorage.getOwnerID(), alicePersonsStorage.getOwnerName(), alicePrivateKey,
                bobID, bobName, bobPublicKey, now);

        // verify
        boolean verified = asapCertificate.verify(alicePublicKey);
        Assert.assertTrue(verified);
    }

    @Test
    public void certificateVerifyTest2() throws
            IOException, ASAPException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, SharkException {

        ASAPEngineFS.removeFolder(ROOT_DIRECTORY);

        long now = System.currentTimeMillis();

        // setup alice
        ASAPEngine aliceASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_ALICE, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPCertificateStorageImpl(aliceASAPStorage, ALICE_ID, ALICE_NAME);
        PersonsStorage alicePersonsStorage = new PersonsStorageImpl(asapAliceCertificateStorage);

        // setup bob
        ASAPEngine bobASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_BOB, ASAPCertificateStorage.APP_NAME);
        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPCertificateStorageImpl(aliceASAPStorage, BOB_ID, BOB_NAME);
        PersonsStorage bobPersonsStorage = new PersonsStorageImpl(asapBobCertificateStorage);

        // simulation - Bob must send its credentials in some way to Alice - assume that happened
        CharSequence bobID = bobPersonsStorage.getOwnerID();
        CharSequence bobName = bobPersonsStorage.getOwnerName();
        PublicKey bobPublicKey = bobPersonsStorage.getPublicKey();

        PublicKey alicePublicKey = alicePersonsStorage.getPublicKey();
        PrivateKey alicePrivateKey = alicePersonsStorage.getPrivateKey();

        // alice signs a certificate of bob
        ASAPCertificate asapCertificate = alicePersonsStorage.addAndSignPerson(bobID, bobName, bobPublicKey, now);

        // verify
        Assert.assertTrue(asapCertificate.verify(alicePublicKey));
    }
}
