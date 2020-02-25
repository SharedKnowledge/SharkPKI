package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.InMemoCertificateStorageImpl;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.IOException;

public class InMemoPersonsStorageImpl extends PersonsStorageImpl {
    public static final CharSequence ALICE_ID = "42";
    public static final CharSequence ALICE_NAME = "Alice";
    public static final CharSequence BOB_ID = "43";
    public static final CharSequence BOB_NAME = "Bob";
    public static final CharSequence CLARA_ID = "44";
    public static final CharSequence CLARA_NAME = "Clara";
    public static final CharSequence DAVID_ID = "45";
    public static final CharSequence DAVID_NAME = "David";

    public InMemoPersonsStorageImpl(CharSequence ownerID, CharSequence ownerName) {
        super(new InMemoCertificateStorageImpl(ownerID, ownerName));
    }

    public void fillWithExampleData() throws SharkException, IOException {
        // fill with example data - usually we assume Alice to be owner and build that chain...
        ASAPCertificateStorage certificateStorage;
        PersonsStorage aliceStorage, bobStorage = null, claraStorage = null, davidStorage;

        // Alice
        if(!this.getOwnerID().toString().equalsIgnoreCase(ALICE_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(ALICE_ID, ALICE_NAME);
            aliceStorage = new PersonsStorageImpl(certificateStorage);
            this.addAndSignPerson(ALICE_ID, ALICE_NAME, aliceStorage.getPublicKey());
        }

        // Bob
        if(!this.getOwnerID().toString().equalsIgnoreCase(BOB_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(BOB_ID, BOB_NAME);
            bobStorage = new PersonsStorageImpl(certificateStorage);
            this.addAndSignPerson(BOB_ID, BOB_NAME, bobStorage.getPublicKey());
        }

        // Clara
        if(!this.getOwnerID().toString().equalsIgnoreCase(CLARA_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(CLARA_ID, CLARA_NAME);
            claraStorage = new PersonsStorageImpl(certificateStorage);
            if(bobStorage != null) {
                ASAPCertificate asapCertificate =
                        bobStorage.addAndSignPerson(CLARA_ID, CLARA_NAME, claraStorage.getPublicKey());
                this.addCertificate(asapCertificate);
            }
        }

        // David
        if(!this.getOwnerID().toString().equalsIgnoreCase(DAVID_ID.toString())) {
            certificateStorage = new InMemoCertificateStorageImpl(DAVID_ID, DAVID_NAME);
            davidStorage = new PersonsStorageImpl(certificateStorage);
            if(claraStorage != null) {
                ASAPCertificate asapCertificate =
                    claraStorage.addAndSignPerson(DAVID_ID, DAVID_NAME, davidStorage.getPublicKey());
                this.addCertificate(asapCertificate);
            }
        }
    }
}
