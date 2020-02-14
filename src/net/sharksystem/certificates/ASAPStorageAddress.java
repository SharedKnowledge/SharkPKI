package net.sharksystem.certificates;

public interface ASAPStorageAddress {
    CharSequence getFormat();
    CharSequence getUri();
    int getEra();
    byte[] asBytes();
}
