package net.sharksystem.asap.persons;

import net.sharksystem.fs.FSUtils;
import net.sharksystem.pki.TestConstants;
import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;
import net.sharksystem.asap.engine.ASAPEngine;
import net.sharksystem.asap.engine.ASAPEngineFS;
import net.sharksystem.asap.pki.ASAPStorageBasedCertificates;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateImpl;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.*;
import java.util.Collection;

import static net.sharksystem.pki.TestConstants.*;

public class ASAPCertificateStoreTests {
    private static final String SPECIFIC_ROOT_DIRECTORY = TestConstants.ROOT_DIRECTORY + "/asapStorageRootDirectory/";
    private static final String ROOT_DIRECTORY_ALICE = SPECIFIC_ROOT_DIRECTORY + ALICE_NAME;
    private static final String ROOT_DIRECTORY_BOB = SPECIFIC_ROOT_DIRECTORY + BOB_NAME;
    private static final String ROOT_DIRECTORY_CLARA = SPECIFIC_ROOT_DIRECTORY + TestConstants.CLARA_NAME;
    private static final String ROOT_DIRECTORY_DAVID = SPECIFIC_ROOT_DIRECTORY + TestConstants.DAVID_NAME;

    private void assertCertificateEquals(ASAPCertificate a, ASAPCertificate b) {
        Assert.assertEquals(a.getIssuerID(), b.getIssuerID());
        Assert.assertEquals(a.getSubjectID(), b.getSubjectID());
        Assert.assertEquals(a.getSubjectName(), b.getSubjectName());
        Assert.assertEquals(a.getIssuerName(), b.getIssuerName());
    }

    @Test
    public void identityAssuranceCalculationTest() throws IOException, ASAPException {
        FSUtils.removeFolder(SPECIFIC_ROOT_DIRECTORY);

        long now = System.currentTimeMillis();

        // setup alice
        ASAPEngine aliceASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_ALICE, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPStorageBasedCertificates(aliceASAPStorage, ALICE_ID, ALICE_NAME);

        ASAPKeyStore aliceCryptoStorage = new InMemoASAPKeyStore(ALICE_ID);
        ASAPCertificateAndPersonStore aliceASAPCertificateStore = new ASAPCertificateAndPersonStoreImpl(asapAliceCertificateStorage, aliceCryptoStorage);

        // setup bob
        ASAPEngine bobASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_BOB, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPStorageBasedCertificates(aliceASAPStorage, BOB_ID, BOB_NAME);

        ASAPKeyStore bobCryptoStorage = new InMemoASAPKeyStore(BOB_ID);
        ASAPCertificateAndPersonStore bobASAPCertificateStore = new ASAPCertificateAndPersonStoreImpl(asapBobCertificateStorage, bobCryptoStorage);

        // simulation - Bob must send its credentials in some way to Alice - assume that happened
        CharSequence bobID = bobASAPCertificateStore.getOwnerID();
        CharSequence bobName = bobASAPCertificateStore.getOwnerName();
        PublicKey bobPublicKey = bobASAPCertificateStore.getPublicKey();

        // alice signs a certificate of bob
        ASAPCertificate asapCertificate = aliceASAPCertificateStore.addAndSignPerson(bobID, bobName, bobPublicKey, now);

        // Alice could (and should) send it back to Bob - not tested here
        byte[] bytes = asapCertificate.asBytes();

        Assert.assertEquals(OtherPerson.HIGHEST_IDENTITY_ASSURANCE_LEVEL,
                aliceASAPCertificateStore.getIdentityAssurance(bobID));

        // create a certificate of David issued by Clara
        // setup Clara
        ASAPEngine claraASAPStorage = ASAPEngineFS.getASAPStorage(
                "Clara", ROOT_DIRECTORY_CLARA, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapClaraCertificateStorage =
                new ASAPStorageBasedCertificates(claraASAPStorage, CLARA_ID, CLARA_NAME);

        ASAPKeyStore claraCryptoStorage = new InMemoASAPKeyStore(CLARA_ID);
        ASAPCertificateAndPersonStore claraASAPCertificateStore = new ASAPCertificateAndPersonStoreImpl(asapClaraCertificateStorage, claraCryptoStorage);

        // setup David
        ASAPEngine davidASAPStorage = ASAPEngineFS.getASAPStorage(
                "Clara", ROOT_DIRECTORY_DAVID, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapDavidCertificateStorage =
                new ASAPStorageBasedCertificates(davidASAPStorage, DAVID_ID, DAVID_NAME);

        ASAPKeyStore davidCryptoStorage = new InMemoASAPKeyStore(DAVID_ID);
        ASAPCertificateAndPersonStore davidASAPCertificateStore = new ASAPCertificateAndPersonStoreImpl(asapDavidCertificateStorage, davidCryptoStorage);

        // clara signs a certificate of david
        CharSequence davidID = davidASAPCertificateStore.getOwnerID();
        asapCertificate = claraASAPCertificateStore.addAndSignPerson(
                davidID,
                davidASAPCertificateStore.getOwnerName(),
                davidASAPCertificateStore.getPublicKey(), now);

        // add to alice certification storage
        aliceASAPCertificateStore.addCertificate(asapCertificate);

        Collection<ASAPCertificate> davidCerts = aliceASAPCertificateStore.getCertificatesBySubject(davidID);
        Assert.assertNotNull(davidCerts);
        Assert.assertEquals(1, davidCerts.size());

        // alice cannot verify clara - there is no safe way to david
        Assert.assertEquals(OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL,
                aliceASAPCertificateStore.getIdentityAssurance(davidID));

        // bob signs a certificate of clara
        CharSequence claraID = claraASAPCertificateStore.getOwnerID();
        asapCertificate = bobASAPCertificateStore.addAndSignPerson(
                claraID,
                claraASAPCertificateStore.getOwnerName(),
                claraASAPCertificateStore.getPublicKey(), now);

        // add to alice certification storage
        aliceASAPCertificateStore.addCertificate(asapCertificate);

        // alice can verify clara thanks to bob
        int claraIdentityAssurance = aliceASAPCertificateStore.getIdentityAssurance(claraID);
        System.out.println("clara identity assurance on alice side == " + claraIdentityAssurance);
        Assert.assertEquals(5, claraIdentityAssurance);

        // alice can verify david thanks to bob and clara
        int davidIdentityAssurance = aliceASAPCertificateStore.getIdentityAssurance(davidID);
        System.out.println("david identity assurance on alice side == " + davidIdentityAssurance);
        // there is a way from alice to david now - iA is 2.5 rounded up to 3
        Assert.assertEquals(3, aliceASAPCertificateStore.getIdentityAssurance(davidID));

        PersonValues davidValues = aliceASAPCertificateStore.getPersonValuesByID(davidID);
        Assert.assertTrue(davidValues.getName().toString().equalsIgnoreCase(DAVID_NAME));
    }

    @Test
    public void certificateVerifyTest1() throws
            IOException, ASAPException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, ASAPSecurityException {

        FSUtils.removeFolder(SPECIFIC_ROOT_DIRECTORY);

        long now = System.currentTimeMillis();

        // setup alice
        ASAPEngine aliceASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_ALICE, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPStorageBasedCertificates(aliceASAPStorage, ALICE_ID, ALICE_NAME);
        ASAPKeyStore aliceCryptoStorage = new InMemoASAPKeyStore(ALICE_ID);
        ASAPCertificateAndPersonStore aliceASAPCertificateStore = new ASAPCertificateAndPersonStoreImpl(asapAliceCertificateStorage, aliceCryptoStorage);

        // setup bob
        ASAPEngine bobASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_BOB, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPStorageBasedCertificates(aliceASAPStorage, BOB_ID, BOB_NAME);
        ASAPKeyStore bobCryptoStorage = new InMemoASAPKeyStore(BOB_ID);
        ASAPCertificateAndPersonStore bobASAPCertificateStore = new ASAPCertificateAndPersonStoreImpl(asapBobCertificateStorage, bobCryptoStorage);

        // simulation - Bob must send its credentials in some way to Alice - assume that happened
        CharSequence bobID = bobASAPCertificateStore.getOwnerID();
        CharSequence bobName = bobASAPCertificateStore.getOwnerName();
        PublicKey bobPublicKey = bobASAPCertificateStore.getPublicKey();

        PublicKey alicePublicKey = aliceASAPCertificateStore.getPublicKey();
        PrivateKey alicePrivateKey = aliceASAPCertificateStore.getPrivateKey();

        // alice signs a certificate of bob
        ASAPCertificate asapCertificate = ASAPCertificateImpl.produceCertificate(
                aliceASAPCertificateStore.getOwnerID(), aliceASAPCertificateStore.getOwnerName(), alicePrivateKey,
                bobID, bobName, bobPublicKey, now, ASAPCertificateImpl.DEFAULT_SIGNATURE_METHOD);

        // verify
        boolean verified = asapCertificate.verify(alicePublicKey);
        Assert.assertTrue(verified);
    }

    @Test
    public void certificateVerifyTest2() throws
            IOException, ASAPException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, ASAPSecurityException {

        FSUtils.removeFolder(SPECIFIC_ROOT_DIRECTORY);

        long now = System.currentTimeMillis();

        // setup alice
        ASAPEngine aliceASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_ALICE, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapAliceCertificateStorage =
                new ASAPStorageBasedCertificates(aliceASAPStorage, ALICE_ID, ALICE_NAME);
        ASAPKeyStore aliceCryptoStorage = new InMemoASAPKeyStore(ALICE_ID);
        ASAPCertificateAndPersonStore aliceASAPCertificateStore =
                new ASAPCertificateAndPersonStoreImpl(asapAliceCertificateStorage, aliceCryptoStorage);

        // setup bob
        ASAPEngine bobASAPStorage = ASAPEngineFS.getASAPStorage(
                "Alice", ROOT_DIRECTORY_BOB, ASAPCertificateStorage.PKI_APP_NAME);
        ASAPCertificateStorage asapBobCertificateStorage =
                new ASAPStorageBasedCertificates(aliceASAPStorage, BOB_ID, BOB_NAME);
        ASAPKeyStore bobCryptoStorage = new InMemoASAPKeyStore(BOB_ID);
        ASAPCertificateAndPersonStore bobASAPCertificateStore =
                new ASAPCertificateAndPersonStoreImpl(asapBobCertificateStorage, bobCryptoStorage);

        // simulation - Bob must send its credentials in some way to Alice - assume that happened
        CharSequence bobID = bobASAPCertificateStore.getOwnerID();
        CharSequence bobName = bobASAPCertificateStore.getOwnerName();
        PublicKey bobPublicKey = bobASAPCertificateStore.getPublicKey();

        PublicKey alicePublicKey = aliceASAPCertificateStore.getPublicKey();
        PrivateKey alicePrivateKey = aliceASAPCertificateStore.getPrivateKey();

        // alice signs a certificate of bob
        ASAPCertificate asapCertificate = aliceASAPCertificateStore.addAndSignPerson(bobID, bobName, bobPublicKey, now);

        // verify
        Assert.assertTrue(asapCertificate.verify(alicePublicKey));
    }
}
