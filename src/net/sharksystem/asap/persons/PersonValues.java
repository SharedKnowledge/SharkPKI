package net.sharksystem.asap.persons;

public interface PersonValues {
    int DEFAULT_SIGNING_FAILURE_RATE = 5;

    /**
     * Id can not be changed
     * @return
     */
    CharSequence getUserID();

    /**
     * Name can be changed
     * @return
     */
    CharSequence getName();

    void setName(CharSequence name);

    int getSigningFailureRate();

    void setSigningFailureRate(int failureRate);
}
