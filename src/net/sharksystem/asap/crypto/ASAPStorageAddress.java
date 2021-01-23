package net.sharksystem.asap.crypto;

public interface ASAPStorageAddress {
    CharSequence getFormat();
    CharSequence getUri();
    int getEra();
    byte[] asBytes();
}
