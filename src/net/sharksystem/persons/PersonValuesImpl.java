package net.sharksystem.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.util.Log;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class PersonValuesImpl implements PersonValues {
    private final CharSequence id;
    private CharSequence name;
    private int signingFailureRate;

    private final ASAPCertificateStorage certificateStorage;
    private final PersonsStorageImpl personsStorage;

    public PersonValuesImpl(CharSequence id, CharSequence name, ASAPCertificateStorage certificateStorage,
                            PersonsStorageImpl personsStorage) {

        this.id = id;
        this.name = name;
        this.certificateStorage = certificateStorage;
        this.personsStorage = personsStorage;
        this.signingFailureRate = DEFAULT_SIGNING_FAILURE_RATE;
    }

    /**
     * Create object from data stream
     * @param dis
     * @param certificateStorage
     * @param personsStorage
     */
    PersonValuesImpl(DataInputStream dis, ASAPCertificateStorage certificateStorage, PersonsStorageImpl personsStorage)
            throws IOException {

        this.certificateStorage = certificateStorage;
        this.personsStorage = personsStorage;

        this.id = dis.readUTF();
        this.name = dis.readUTF();
        this.signingFailureRate = dis.readInt();
    }

    /**
     * Write object to data stream
     * @param dos
     */
    public void writePersonValues(DataOutputStream dos) throws IOException {
        dos.writeUTF(this.id.toString());
        dos.writeUTF(this.name.toString());
        dos.writeInt(this.signingFailureRate);
    }

    @Override
    public CharSequence getUserID() { return this.id;}
    @Override
    public CharSequence getName() { return this.name;}

    @Override
    public void setName(CharSequence name) {
        this.name = name;
        this.personsStorage.save();
    }

    @Override
    public int getIdentityAssurance() {
        try {
            return this.certificateStorage.getIdentityAssurances(this.getUserID(), this.personsStorage);
        } catch (ASAPSecurityException e) {
            Log.writeLogErr(this, "cannot calculate identity assurance: " + e.getLocalizedMessage());
            return OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL;
        }
    }

    @Override
    public int getSigningFailureRate() { return this.signingFailureRate;}

    @Override
    public void setSigningFailureRate(int failureRate) {
        this.signingFailureRate = failureRate;
        this.personsStorage.save();
    }
}
