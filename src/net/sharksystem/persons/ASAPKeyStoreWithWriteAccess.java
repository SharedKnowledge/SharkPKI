package net.sharksystem.persons;

import net.sharksystem.crypto.ASAPKeyStorage;

public interface ASAPKeyStoreWithWriteAccess extends ASAPKeyStorage,
        ASAPKeyStoreWriteAccess {
}
