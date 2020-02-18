package net.sharksystem.persons;

public class PersonValues {
    public static final int DEFAULT_CERTIFICATE_EXCHANGE_FAILURE = 5;
    private static final int IDENTITY_ASSURANCE_NOT_CALCULATED = -1;

    private final int id;
    private CharSequence name;
    private int certificateExchangeFailure;
    private int identityAssurance;

    public PersonValues(int id, CharSequence name) {

        this.id = id;
        this.name = name;
        this.identityAssurance = IDENTITY_ASSURANCE_NOT_CALCULATED;
        this.certificateExchangeFailure = DEFAULT_CERTIFICATE_EXCHANGE_FAILURE;
    }

    public int getUserID() { return this.id;}
    public CharSequence getName() { return this.name;}
    public int getIdentityAssurance() { return this.identityAssurance;}
    public int getCertificateExchangeFailure() { return this.certificateExchangeFailure;}

    public void setIdentityAssurance(int identityAssuranceLevel) {
        this.identityAssurance = identityAssuranceLevel;
    }

    public void setCertificateExchangeFailure(int failureRate) {
        this.certificateExchangeFailure = failureRate;
    }
}
