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
        SampleFullAsapPKIStorage personsStorage =
                new SampleFullAsapPKIStorage(ALICE_ID, ALICE_NAME);

        personsStorage.fillWithExampleData();

        Collection<ASAPCertificate> certificate =
                personsStorage.getCertificatesBySubject(SampleFullAsapPKIStorage.FRANCIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleFullAsapPKIStorage.GLORIA_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleFullAsapPKIStorage.HASSAN_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(SampleFullAsapPKIStorage.IRIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        PersonValuesImpl personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.FRANCIS_ID);
        Assert.assertNotNull(personValues);
        int iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.GLORIA_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA);

        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.HASSAN_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(3, iA);

        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.IRIS_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(1, iA);

        // change cef(francis) to best
        personsStorage.setSigningFailureRate(
                SampleFullAsapPKIStorage.FRANCIS_ID,1);

        // check again
        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.FRANCIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.GLORIA_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(9, iA);

        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.HASSAN_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA); // 4.5

        personValues = personsStorage.getPersonValues(SampleFullAsapPKIStorage.IRIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(2, iA); // 2.25

        ///////////////// lists
        Collection<ASAPCertificate> francisOwnerCerts =
                personsStorage.getCertificatesBySubject(SampleFullAsapPKIStorage.FRANCIS_ID);

        Assert.assertEquals(1, francisOwnerCerts.size());
        Assert.assertTrue(francisOwnerCerts.iterator().next().getIssuerID().toString()
                .equalsIgnoreCase(ALICE_ID));

        Collection<ASAPCertificate> francisSignerCerts =
                personsStorage.getCertificatesByIssuer(SampleFullAsapPKIStorage.FRANCIS_ID);

        Assert.assertEquals(1, francisSignerCerts.size());
        Assert.assertTrue(francisSignerCerts.iterator().next().getSubjectID().toString()
                .equalsIgnoreCase(SampleFullAsapPKIStorage.GLORIA_ID.toString()));

        List<CharSequence> path =
                personsStorage.getIdentityAssurancesCertificationPath(SampleFullAsapPKIStorage.FRANCIS_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleFullAsapPKIStorage.GLORIA_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleFullAsapPKIStorage.HASSAN_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(SampleFullAsapPKIStorage.IRIS_ID);
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
        ASAPCertificateStore freshASAPCertificateStore = new SampleFullAsapPKIStorage(ALICE_ID, ALICE_NAME);

        // load
        freshASAPCertificateStore.load(is);

        // test
        Assert.assertEquals(expectedSize, freshASAPCertificateStore.getNumberOfPersons());
        freshASAPCertificateStore.getIdentityAssurance(SampleFullAsapPKIStorage.FRANCIS_ID);
        freshASAPCertificateStore.getIdentityAssurance(SampleFullAsapPKIStorage.GLORIA_ID);
        freshASAPCertificateStore.getIdentityAssurance(SampleFullAsapPKIStorage.HASSAN_ID);
        freshASAPCertificateStore.getIdentityAssurance(SampleFullAsapPKIStorage.IRIS_ID);
    }
}
