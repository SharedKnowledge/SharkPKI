package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.crypto.ASAPCertificate;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Collection;

public class InMemoHelperTests {

    @Test
    public void test1() throws SharkException, IOException {
        InMemoPersonsStorageImpl personsStorage = new InMemoPersonsStorageImpl("AliceID", "Alice");
        personsStorage.fillWithExampleData();

        Collection<ASAPCertificate> certificate = personsStorage.getCertificateByOwner(InMemoPersonsStorageImpl.BOB_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificateByOwner(InMemoPersonsStorageImpl.CLARA_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        certificate = personsStorage.getCertificateByOwner(InMemoPersonsStorageImpl.DAVID_ID);
        Assert.assertNotNull(certificate);
        Assert.assertFalse(certificate.isEmpty());

        PersonValuesImpl personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.BOB_ID);
        Assert.assertNotNull(personValues);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.CLARA_ID);
        Assert.assertNotNull(personValues);

        personValues = personsStorage.getPersonValues(InMemoPersonsStorageImpl.DAVID_ID);
        Assert.assertNotNull(personValues);

        int identityAssurance = personsStorage.getIdentityAssurance(InMemoPersonsStorageImpl.DAVID_ID);
        System.out.println(identityAssurance);
    }
}
