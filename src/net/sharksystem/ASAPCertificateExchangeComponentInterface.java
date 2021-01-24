package net.sharksystem;

import net.sharksystem.asap.crypto.ASAPCertificateStorage;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.persons.ASAPCertificateStore;

@ASAPFormats(formats = {ASAPCertificateStore.CREDENTIAL_APP_NAME,ASAPCertificateStorage.CERTIFICATE_APP_NAME})
public interface ASAPCertificateExchangeComponentInterface extends
        SharkComponent, // make this project a Shark component
        ASAPKeyStore, ASAPCertificateStore // sum of all supported interfaces
{
}
