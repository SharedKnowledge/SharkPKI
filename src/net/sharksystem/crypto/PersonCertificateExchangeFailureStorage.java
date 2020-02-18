package net.sharksystem.crypto;

import net.sharksystem.SharkException;

public interface PersonCertificateExchangeFailureStorage {
    int getCertificateExchangeFailure(int personID) throws SharkException;
}
