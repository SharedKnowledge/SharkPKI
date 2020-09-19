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
        InMemoPersonsStorageImpl personsStorage =
                new InMemoPersonsStorageImpl(ALICE_ID, ALICE_NAME);

        personsStorage.fillWithExampleData();

        Collection<ASAPCertificate> certificate =
                personsStorage.getCertificatesBySubject(InMemoPersonsStorageImpl.FRANCIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(InMemoPersonsStorageImpl.GLORIA_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(InMemoPersonsStorageImpl.HASSAN_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificatesBySubject(InMemoPersonsStorageImpl.IRIS_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        PersonValuesImpl personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.FRANCIS_ID);
        Assert.assertNotNull(personValues);
        int iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.GLORIA_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.HASSAN_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(3, iA);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.IRIS_ID);
        Assert.assertNotNull(personValues);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(1, iA);

        // change cef(francis) to best
        personsStorage.setSigningFailureRate(
                InMemoPersonsStorageImpl.FRANCIS_ID,1);

        // check again
        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.FRANCIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(10, iA);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.GLORIA_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(9, iA);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.HASSAN_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(5, iA); // 4.5

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.IRIS_ID);
        iA = personValues.getIdentityAssurance();
        System.out.println(iA);
        Assert.assertEquals(2, iA); // 2.25

        ///////////////// lists
        Collection<ASAPCertificate> francisOwnerCerts =
                personsStorage.getCertificatesBySubject(InMemoPersonsStorageImpl.FRANCIS_ID);

        Assert.assertEquals(1, francisOwnerCerts.size());
        Assert.assertTrue(francisOwnerCerts.iterator().next().getIssuerID().toString()
                .equalsIgnoreCase(ALICE_ID));

        Collection<ASAPCertificate> francisSignerCerts =
                personsStorage.getCertificatesByIssuer(InMemoPersonsStorageImpl.FRANCIS_ID);

        Assert.assertEquals(1, francisSignerCerts.size());
        Assert.assertTrue(francisSignerCerts.iterator().next().getSubjectID().toString()
                .equalsIgnoreCase(InMemoPersonsStorageImpl.GLORIA_ID.toString()));

        List<CharSequence> path =
                personsStorage.getIdentityAssurancesCertificationPath(InMemoPersonsStorageImpl.FRANCIS_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(InMemoPersonsStorageImpl.GLORIA_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(InMemoPersonsStorageImpl.HASSAN_ID);
        System.out.println(path);

        path = personsStorage.getIdentityAssurancesCertificationPath(InMemoPersonsStorageImpl.IRIS_ID);
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
        PersonsStorage freshPersonsStorage = new InMemoPersonsStorageImpl(ALICE_ID, ALICE_NAME);

        // load
        freshPersonsStorage.load(is);

        // test
        Assert.assertEquals(expectedSize, freshPersonsStorage.getNumberOfPersons());
        freshPersonsStorage.getIdentityAssurance(InMemoPersonsStorageImpl.FRANCIS_ID);
        freshPersonsStorage.getIdentityAssurance(InMemoPersonsStorageImpl.GLORIA_ID);
        freshPersonsStorage.getIdentityAssurance(InMemoPersonsStorageImpl.HASSAN_ID);
        freshPersonsStorage.getIdentityAssurance(InMemoPersonsStorageImpl.IRIS_ID);
    }
}
