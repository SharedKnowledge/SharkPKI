package net.sharksystem.persons;

public interface PersonValues {
    int DEFAULT_CERTIFICATE_EXCHANGE_FAILURE = 5;

    CharSequence getUserID();

    CharSequence getName();

    void setName(CharSequence name);

    int getIdentityAssurance();

    int getSigningFailureRate();

    void setSigningFailureRate(int failureRate);
}
