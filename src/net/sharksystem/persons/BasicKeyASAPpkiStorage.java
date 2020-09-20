package net.sharksystem.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.ASAPKeyStorage;

public class BasicKeyASAPpkiStorage extends ASAPPKIImpl {
    public BasicKeyASAPpkiStorage(ASAPCertificateStorage certificateStorage,
                                  ASAPKeyStorage asapKeyStorage, String signingAlgorithm)
            throws ASAPSecurityException {

        super(certificateStorage, asapKeyStorage, signingAlgorithm);
    }

    public BasicKeyASAPpkiStorage(ASAPCertificateStorage certificateStorage)
            throws ASAPSecurityException {

        super(certificateStorage);
    }
}
