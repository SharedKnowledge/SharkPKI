package net.sharksystem.persons;

public interface PersonValues {
    int DEFAULT_CERTIFICATE_EXCHANGE_FAILURE = 5;

    int getUserID();

    CharSequence getName();

    void setName(CharSequence name);

    int getIdentityAssurance();

    int getCertificateExchangeFailure();

    void setCertificateExchangeFailure(int failureRate);
}
