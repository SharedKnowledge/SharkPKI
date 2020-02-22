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

    public PrivateKey getPrivateKey() {
        return this.rsaKeyPair.getPrivate();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                           other persons management - in memory                           //
    //////////////////////////////////////////////////////////////////////////////////////////////

    private List<PersonValuesImpl> personsList = new ArrayList<>();

    public PersonValuesImpl getPersonValues(int userID) throws SharkException {
        for(PersonValuesImpl personValues : this.personsList) {
            if(personValues.getUserID() == userID) {
                return personValues;
            }
        }

        throw new SharkException("person not found with userID: " + userID);
    }

    public PersonValuesImpl getPersonValuesByPosition(int position) throws SharkException {
        try {
            PersonValuesImpl personValues = this.personsList.get(position);
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

        // try to overwrite owner ?
        if(userID == this.getOwnerUserID()) {
            throw new SharkCryptoException("cannot add person with your userID");
        }

        // already in there
        for(PersonValuesImpl personValues : this.personsList) {
            if(personValues.getUserID() == userID) {
                throw new SharkCryptoException("person with userID already exists: " + userID);
            }
        }

        // ok - add
        PersonValuesImpl newPersonValues = new PersonValuesImpl(userID, userName, this.certificateStorage, this);
        this.personsList.add(newPersonValues);

        // is there already a certificate?
        try {
            Collection<ASAPCertificate> certificates = this.getCertificate(userID);
            for(ASAPCertificate certTemp : certificates) {
                if(certTemp.getSignerID() == this.getOwnerUserID()) {
                    // drop it
                    this.certificateStorage.removeCertificate(certTemp);
                }
            }
        } catch (SharkException e) {
            e.printStackTrace();
        }

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

            return cert;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.writeLogErr(this, "cannot create certificate: " + e.getLocalizedMessage());
            e.printStackTrace();
            throw new SharkCryptoException("cannot create certificate: " + e.getLocalizedMessage());
        }
    }

    @Override
    public void addCertificate(ASAPCertificate asapCert) throws IOException, SharkException {
        PersonValuesImpl newPersonValues =
                new PersonValuesImpl(asapCert.getOwnerID(), asapCert.getOwnerName(), this.certificateStorage, this);
        this.personsList.add(newPersonValues);

        this.certificateStorage.storeCertificate(asapCert);
    }

    public Collection<ASAPCertificate> getCertificate(int userID) throws SharkException {
        return this.certificateStorage.getCertificatesByOwnerID(userID);
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
