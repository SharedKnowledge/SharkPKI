package net.sharksystem.crypto;

import net.sharksystem.SharkException;

public class SharkCryptoException extends SharkException {
        public SharkCryptoException() { super(); }

        public SharkCryptoException(String message) { super(message); }

        public SharkCryptoException(String message, Throwable cause) { super(message, cause); }

        public SharkCryptoException(Throwable cause) { super(cause); }
}
