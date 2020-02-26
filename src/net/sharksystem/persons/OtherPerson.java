package net.sharksystem.persons;

public interface OtherPerson extends Person {
    int LOWEST_IDENTITY_ASSURANCE_LEVEL = 0;
    int HIGHEST_IDENTITY_ASSURANCE_LEVEL = 10;

    /**
     * The assurance level is a non-negative integer value between 10 and 0.
     * 10 means: identity of this person can be assured. An assurance level of 10 is only
     * possible if the owner actually met this person is reale life and exchanged keys. All other
     * identities are below 10.
     *
     * 0 means: identity can not be assured at all. This can be due to a lack of any certificate.
     * A zero can also be achieved if a certificate is present can only be verified over a queue of
     * issuers with a high certificate failure rate.
     *
     * The assurance level can be calculated for any other person with a certificate.
     *
     * Assume that the app owner has received a certificate for Alice signed by Bob. Also assumed
     * that the owner actually met Bob before. Assume also that the owner gave Bob a certificate
     * failure rate of 3. That means: The owner assumes Bob get fooled in 30% of certificate exchange.
     *
     * In other words: 70% of certificates signed by Bob are correct. The assurance level is 7.
     *
     * To make it more complex: Assume, the owner has not met Bob but got its certificate from
     * Clara which has got a certificate failure rate of 1 (lowest possible number) which means:
     * It is assumed that
     * Clara is fooled in 10% of certificate exchange. In other words: 90% of Clara's' certificates
     * are correct. Bob has still a failure rate of 3. 70% of his certificates are correct.
     *
     * The owner calculates: 90 % * 70% = 0,9*0,7 = 0,63 = 63%. The assurance level is 6.
     *
     * Assurance level decreases with each additional verification step.
     *
     * @link getCertificateFailureRate()
     * @return assurance level
     */
    int getIdentityAssuranceLevel();

    int YOUR_SIGNING_FAILURE_RATE = 0; // 0% failure - you are perfect of course
    int BEST_SIGNING_FAILURE_RATE = 1; // 10% assumed
    int WORST_SIGNING_FAILURE_RATE = 10; // 100% fully unreliable
    /**
     * Signing failure defines the failure rate when creating new certificates.
     * <br/>
     * Certificates are created. Often, it is a quick act with a deep impact, though.
     * We are humans. We make mistakes. In SharkNet, we accept that fact and work with it.
     * First: We assume, that owner work flawless. That's important. We want user to be fully
     * aware of their actions and implications. Allowing user to rank down their own reliability
     * would allow them to get out of their responsibility. We will not allow that.
     * <br/>
     * Second: Each other person makes failure. There is no perfect guy in my peer group. Same reason:
     * Users must deal with uncertainty. The must recognize failure and be aware of attacks.
     * And they need an incentive to directly meet others and not trust lengthy certificates chains.
     * <br/>
     *
     * The best number is 1 which assumes that 10% of issued certificates are wrong. Number of 10 means:
     * 100% - any certificate is wrong. That is the worst number.
     *
     * Note: That value is for owners personal use only a will never be delivered to others through
     * the Shark Net.
     *
     * @return failure rate between 1 and 10.
     */
    int getCertificateFailureRate();
}
