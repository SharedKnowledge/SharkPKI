package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.util.Log;
import net.sharksystem.crypto.ASAPCertificate;
import net.sharksystem.crypto.ASAPCertificateImpl;
import net.sharksystem.crypto.ASAPCertificateStorage;
import net.sharksystem.crypto.SharkCryptoException;

import java.io.IOException;
import java.security.*;
import java.util.*;

public class PersonsStorageImpl implements PersonsStorage {
    private final ASAPCertificateStorage certificateStorage;
    private KeyPair rsaKeyPair = null;

    public PersonsStorageImpl(ASAPCertificateStorage certificateStorage) {
        this.certificateStorage = certificateStorage;
        this.setup();
    }

    protected void setup() {
        if(this.rsaKeyPair == null) {
            try {
                this.generateKeyPair();
            } catch (Exception e) {
                Log.writeLog(this,"cannot create key pair - fatal");
            }
        }

        Log.writeLog(this, "TODO: re-read certificate from storage when setting up");
    }

    public void generateKeyPair() throws SharkException {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new SharkException(e.getLocalizedMessage());
        }

        SecureRandom secRandom = new SecureRandom();
        try {
            keyGen.initialize(2048, secRandom);
            this.rsaKeyPair = keyGen.generateKeyPair();
        }
        catch(RuntimeException re) {
            throw new SharkException(re.getLocalizedMessage());
        }
    }

    public PublicKey getPublicKey() {
        return this.rsaKeyPair.getPublic();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                           other persons management - in memory                           //
    //////////////////////////////////////////////////////////////////////////////////////////////

    private List<PersonValues> personsList = new ArrayList<>();

    private void fillPersonsWithTestData() throws SharkException {
        this.personsList = new ArrayList<>();
        this.personsList.add(new PersonValues(0, "Person 1"));
        this.personsList.add(new PersonValues(1, "Person 2"));

        this.recalculateIdentityAssurances();
    }

    public PersonValues getPersonValues(int userID) throws SharkException {
        for(PersonValues personValues : this.personsList) {
            if(personValues.getUserID() == userID) {
                return personValues;
            }
        }

        throw new SharkException("person not found with userID: " + userID);
    }

    public PersonValues getPersonValuesByPosition(int position) throws SharkException {
        try {
            PersonValues personValues = this.personsList.get(position);
            return personValues;
        }
        catch(IndexOutOfBoundsException e) {
            throw new SharkException("position too high: " + position);
        }
    }

    public int getNumberOfPersons() {
        return this.personsList.size();
    }

    public int getIdentityAssurance(int userID) throws SharkException {
        return this.getPersonValues(userID).getIdentityAssurance();
    }

    public int getOwnerUserID() {
        return this.certificateStorage.getOwnerID();
    }

    @Override
    public ASAPCertificate addAndSignPerson(int userID, CharSequence userName, PublicKey publicKey)
            throws SharkCryptoException, IOException {

        // already in there
        for(PersonValues personValues : this.personsList) {
            if(personValues.getUserID() == userID) {
                throw new SharkCryptoException("person with userID already exists: " + userID);
            }
        }

        // even owner
        if(userID == this.getOwnerUserID()) {
            throw new SharkCryptoException("cannot add person with your userID");
        }

        PersonValues newPersonValues = new PersonValues(userID, userName);
        this.personsList.add(newPersonValues);

        // sign public key - create certificate and store it.

        ASAPCertificate cert = null;
        try {
            cert = ASAPCertificateImpl.produceCertificate(
                    this.getOwnerUserID(),
                    this.getOwnerName(),
                    this.getPrivateKey(),
                    userID,
                    userName,
                    publicKey);

            // make it persistent
            this.certificateStorage.storeCertificate(cert);

            // re-calculate identity assurance level
            this.recalculateIdentityAssurances();

            return cert;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | SharkException e) {
            Log.writeLogErr(this, "cannot create certificate: " + e.getLocalizedMessage());
            throw new SharkCryptoException("cannot create certificate: " + e.getLocalizedMessage());
        }
    }

    @Override
    public void addCertificate(ASAPCertificate asapCert) throws IOException, SharkException {
        PersonValues newPersonValues = new PersonValues(asapCert.getOwnerID(), asapCert.getOwnerName());
        this.personsList.add(newPersonValues);

        this.certificateStorage.storeCertificate(asapCert);

        this.recalculateIdentityAssurances();
    }

    private void recalculateIdentityAssurances() throws SharkException {
        for(PersonValues person : this.personsList) {
            person.setIdentityAssurance(this.certificateStorage.getIdentityAssurances(person.getUserID(), this));
        }
    }

    public Collection<ASAPCertificate> getCertificate(int userID) throws SharkException {
        return this.certificateStorage.getCertificatesByOwnerID(userID);
    }

    public PrivateKey getPrivateKey() {
        return this.rsaKeyPair.getPrivate();
    }

    public CharSequence getOwnerName() {
        return this.certificateStorage.getOwnerName();
    }

    @Override
    public int getCertificateExchangeFailure(int personID)  {
        try {
            return this.getPersonValues(personID).getCertificateExchangeFailure();
        } catch (SharkException e) {
            // fix that problem by assuming worst failure rate
            return OtherPerson.WORST_CERTIFICATE_EXCHANGE_FAILURE_RATE;
        }
    }

    public void setCertificateExchangeFailure(int personID, int failureRate) throws SharkException {
        this.getPersonValues(personID).setCertificateExchangeFailure(failureRate);
    }
}
