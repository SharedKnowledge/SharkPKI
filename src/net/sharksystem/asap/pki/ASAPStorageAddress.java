package net.sharksystem.asap.pki;

public interface ASAPStorageAddress {
    CharSequence getFormat();
    CharSequence getUri();
    int getEra();
    byte[] asBytes();
}
