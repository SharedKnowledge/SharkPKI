package net.sharksystem;

import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.persons.ASAPCertificateStore;

public interface ASAPCertificateExchangeComponentInterface extends
        SharkComponentInterface, // tag it as component
        ASAPKeyStore, ASAPCertificateStore // sum of all supported interfaces
{}
