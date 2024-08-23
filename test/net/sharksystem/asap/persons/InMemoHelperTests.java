package net.sharksystem.asap.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.pki.ASAPCertificate;
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
        SampleASAPPKIStorage personsStorage =
                new SampleASAPPKIStorage(ALICE_ID, ALICE_NAME);

        personsStorage.fillWithExampleData();

        Collection<ASAPCertificate> certificate =
                personsStorage.getCertificatesBySubject(SampleASAPPKIStorage.FRANCIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleASAPPKIStorage.GLORIA_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleASAPPKIStorage.HASSAN_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleASAPPKIStorage.IRIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        PersonValuesImpl personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.FRANCIS_ID);
        Assert.assertNotNull(personValues);
        int iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.GLORIA_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA);

        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.HASSAN_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(3, iA);

        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.IRIS_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(1, iA);

        // change cef(francis) to best
        personsStorage.setSigningFailureRate(
                SampleASAPPKIStorage.FRANCIS_ID,1);

        // check again
        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.FRANCIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.GLORIA_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(9, iA);

        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.HASSAN_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA); // 4.5

        personValues = personsStorage.getPersonValues(SampleASAPPKIStorage.IRIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(2, iA); // 2.25

        ///////////////// lists
        Collection<ASAPCertificate> francisOwnerCerts =
                personsStorage.getCertificatesBySubject(SampleASAPPKIStorage.FRANCIS_ID);

        Assert.assertEquals(1, francisOwnerCerts.size());
        Assert.assertTrue(francisOwnerCerts.iterator().next().getIssuerID().toString()
                .equalsIgnoreCase(ALICE_ID));

        Collection<ASAPCertificate> francisSignerCerts =
                personsStorage.getCertificatesByIssuer(SampleASAPPKIStorage.FRANCIS_ID);

        Assert.assertEquals(1, francisSignerCerts.size());
        Assert.assertTrue(francisSignerCerts.iterator().next().getSubjectID().toString()
                .equalsIgnoreCase(SampleASAPPKIStorage.GLORIA_ID.toString()));

        List<CharSequence> path =
                personsStorage.getIdentityAssurancesCertificationPath(SampleASAPPKIStorage.FRANCIS_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleASAPPKIStorage.GLORIA_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleASAPPKIStorage.HASSAN_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleASAPPKIStorage.IRIS_ID);
        System.out.println(path);

        // test persistence

        // simulate storage
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int expectedSize = personsStorage.getNumberOfPersons();
        personsStorage.savetoStream(baos);

        // extract persistent storage
        byte[] persistentStorage = baos.toByteArray();

        // setup input
        InputStream is = new ByteArrayInputStream(persistentStorage);
        ASAPCertificateAndPersonStore freshASAPCertificateStore = new SampleASAPPKIStorage(ALICE_ID, ALICE_NAME);

        // load
        freshASAPCertificateStore.restoreFromStream(is);

        // test
        Assert.assertEquals(expectedSize, freshASAPCertificateStore.getNumberOfPersons());
        freshASAPCertificateStore.getIdentityAssurance(SampleASAPPKIStorage.FRANCIS_ID);
        freshASAPCertificateStore.getIdentityAssurance(SampleASAPPKIStorage.GLORIA_ID);
        freshASAPCertificateStore.getIdentityAssurance(SampleASAPPKIStorage.HASSAN_ID);
        freshASAPCertificateStore.getIdentityAssurance(SampleASAPPKIStorage.IRIS_ID);
    }
}
