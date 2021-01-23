package net.sharksystem.asap.persons;

import net.sharksystem.asap.crypto.ASAPKeyStorage;

public interface ASAPKeyStoreWithWriteAccess extends ASAPKeyStorage,
        ASAPKeyStoreWriteAccess {
}
