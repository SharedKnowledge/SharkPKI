package net.sharksystem.persons;

import net.sharksystem.asap.util.Log;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.SharkCryptoException;

public class PersonValuesImpl implements PersonValues {
    private static final int IDENTITY_ASSURANCE_NOT_CALCULATED = -1;

    private final int id;
    private final ASAPCertificateStorage certificateStorage;
    private final PersonsStorage personsStorage;
    private CharSequence name;
    private int certificateExchangeFailure;

    public PersonValuesImpl(int id, CharSequence name, ASAPCertificateStorage certificateStorage,
                            PersonsStorage personsStorage) {

        this.id = id;
        this.name = name;
        this.certificateStorage = certificateStorage;
        this.personsStorage = personsStorage;
        this.certificateExchangeFailure = DEFAULT_CERTIFICATE_EXCHANGE_FAILURE;
    }

    @Override
    public int getUserID() { return this.id;}
    @Override
    public CharSequence getName() { return this.name;}

    @Override
    public void setName(CharSequence name) {
        this.name = name;
    }

    @Override
    public int getIdentityAssurance() {
        try {
            return this.certificateStorage.getIdentityAssurances(this.getUserID(), this.personsStorage);
        } catch (SharkCryptoException e) {
            Log.writeLogErr(this, "cannot calculate identity assurance: " + e.getLocalizedMessage());
            return OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL;
        }
    }

    @Override
    public int getCertificateExchangeFailure() { return this.certificateExchangeFailure;}

    @Override
    public void setCertificateExchangeFailure(int failureRate) {
        this.certificateExchangeFailure = failureRate;
    }
}
