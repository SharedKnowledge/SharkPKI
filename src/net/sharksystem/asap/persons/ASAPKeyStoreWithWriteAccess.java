package net.sharksystem.asap.persons;

import net.sharksystem.asap.pki.ASAPKeyStorage;

public interface ASAPKeyStoreWithWriteAccess extends ASAPKeyStorage,
        ASAPKeyStoreWriteAccess {
}
