package net.sharksystem.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.crypto.ASAPCertificate;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;

public class InMemoHelperTests {
    public static final String ALICE_ID = "1";
    public static final String ALICE_NAME = "Alice";

    @Test
    public void test1() throws ASAPSecurityException, IOException {
        SampleBasicKeyASAPpkiStorage personsStorage =
                new SampleBasicKeyASAPpkiStorage(ALICE_ID, ALICE_NAME);

        personsStorage.fillWithExampleData();

        Collection<ASAPCertificate> certificate =
                personsStorage.getCertificatesBySubject(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleBasicKeyASAPpkiStorage.GLORIA_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleBasicKeyASAPpkiStorage.HASSAN_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleBasicKeyASAPpkiStorage.IRIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        PersonValuesImpl personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);
        Assert.assertNotNull(personValues);
        int iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.GLORIA_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA);

        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.HASSAN_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(3, iA);

        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.IRIS_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(1, iA);

        // change cef(francis) to best
        personsStorage.setSigningFailureRate(
                SampleBasicKeyASAPpkiStorage.FRANCIS_ID,1);

        // check again
        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.GLORIA_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(9, iA);

        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.HASSAN_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA); // 4.5

        personValues = personsStorage.getPersonValues(SampleBasicKeyASAPpkiStorage.IRIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(2, iA); // 2.25

        ///////////////// lists
        Collection<ASAPCertificate> francisOwnerCerts =
                personsStorage.getCertificatesBySubject(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);

        Assert.assertEquals(1, francisOwnerCerts.size());
        Assert.assertTrue(francisOwnerCerts.iterator().next().getIssuerID().toString()
                .equalsIgnoreCase(ALICE_ID));

        Collection<ASAPCertificate> francisSignerCerts =
                personsStorage.getCertificatesByIssuer(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);

        Assert.assertEquals(1, francisSignerCerts.size());
        Assert.assertTrue(francisSignerCerts.iterator().next().getSubjectID().toString()
                .equalsIgnoreCase(SampleBasicKeyASAPpkiStorage.GLORIA_ID.toString()));

        List<CharSequence> path =
                personsStorage.getIdentityAssurancesCertificationPath(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleBasicKeyASAPpkiStorage.GLORIA_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleBasicKeyASAPpkiStorage.HASSAN_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleBasicKeyASAPpkiStorage.IRIS_ID);
        System.out.println(path);

        // test persistence

        // simulate storage
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int expectedSize = personsStorage.getNumberOfPersons();
        personsStorage.store(baos);

        // extract persistent storage
        byte[] persistentStorage = baos.toByteArray();

        // setup input
        InputStream is = new ByteArrayInputStream(persistentStorage);
        ASAPPKI freshASAPPKI = new SampleBasicKeyASAPpkiStorage(ALICE_ID, ALICE_NAME);

        // load
        freshASAPPKI.load(is);

        // test
        Assert.assertEquals(expectedSize, freshASAPPKI.getNumberOfPersons());
        freshASAPPKI.getIdentityAssurance(SampleBasicKeyASAPpkiStorage.FRANCIS_ID);
        freshASAPPKI.getIdentityAssurance(SampleBasicKeyASAPpkiStorage.GLORIA_ID);
        freshASAPPKI.getIdentityAssurance(SampleBasicKeyASAPpkiStorage.HASSAN_ID);
        freshASAPPKI.getIdentityAssurance(SampleBasicKeyASAPpkiStorage.IRIS_ID);
    }
}
