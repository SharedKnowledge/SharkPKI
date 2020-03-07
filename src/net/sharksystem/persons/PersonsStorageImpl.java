package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.util.Log;
import net.sharksystem.crypto.*;

import java.io.IOException;
import java.security.*;
import java.util.*;

import static net.sharksystem.crypto.ASAPCertificateImpl.DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS;

public class PersonsStorageImpl implements PersonsStorage {
    private final ASAPCertificateStorage certificateStorage;
    private final ASAPKeyStorage asapKeyStorage;

    public PersonsStorageImpl(ASAPCertificateStorage certificateStorage) throws SharkException {
        this(certificateStorage, new InMemoASAPKeyStorage());
    }

    public PersonsStorageImpl(ASAPCertificateStorage certificateStorage,
                              ASAPKeyStorage asapKeyStorage) throws SharkException {
        this.certificateStorage = certificateStorage;
        this.asapKeyStorage = asapKeyStorage;

        Calendar createCal = null;
        try {
            long creationTime = this.asapKeyStorage.getCreationTime(); // throws exception if not set

            // check expiration time
            createCal = ASAPCertificateImpl.long2Calendar(creationTime);
            createCal.add(Calendar.YEAR, DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS);
            if(createCal.getTimeInMillis() > System.currentTimeMillis()) {
                Log.writeLog(this, "local key pair expired - reset");
                this.asapKeyStorage.generateKeyPair();
            }
        } catch (SharkCryptoException e) {
            Log.writeLog(this, "failure receiving keys: " + e.getLocalizedMessage());
            this.asapKeyStorage.generateKeyPair();
        }
    }

    public PublicKey getPublicKey() throws SharkCryptoException {
        return this.asapKeyStorage.getPublicKey();
    }

    public PrivateKey getPrivateKey() throws SharkCryptoException {
        return this.asapKeyStorage.getPrivateKey();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                           other persons management - in memory                           //
    //////////////////////////////////////////////////////////////////////////////////////////////

    private List<PersonValuesImpl> personsList = new ArrayList<>();

    public PersonValuesImpl getPersonValues(CharSequence userID) throws SharkException {
        for(PersonValuesImpl personValues : this.personsList) {
            if(personValues.getUserID().toString().equalsIgnoreCase(userID.toString())) {
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

    public int getIdentityAssurance(CharSequence userID) throws SharkException {
        return this.getPersonValues(userID).getIdentityAssurance();
    }

    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID)
            throws SharkCryptoException {

        return this.certificateStorage.
                getIdentityAssurancesCertificationPath(userID, this);
    }

    public CharSequence getOwnerID() {
        return this.certificateStorage.getOwnerID();
    }

    @Override
    public ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey)
            throws SharkCryptoException, IOException {

        // try to overwrite owner ?
        if(userID.toString().equalsIgnoreCase(this.getOwnerID().toString())) {
            throw new SharkCryptoException("cannot add person with your userID");
        }

        // already in there
        for(PersonValuesImpl personValues : this.personsList) {
            if(userID.toString().equalsIgnoreCase(personValues.getUserID().toString())) {
                throw new SharkCryptoException("person with userID already exists: " + userID);
            }
        }

        // ok - add
        PersonValuesImpl newPersonValues =
                new PersonValuesImpl(userID, userName, this.certificateStorage, this);
        this.personsList.add(newPersonValues);

        // is there already a certificate?
        try {
            Collection<ASAPCertificate> certificates = this.getCertificateByOwner(userID);
            for(ASAPCertificate certTemp : certificates) {
                if(certTemp.getSignerID().toString().equalsIgnoreCase(this.getOwnerID().toString())) {
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
                    this.getOwnerID(),
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

    public Collection<ASAPCertificate> getCertificateByOwner(CharSequence userID) throws SharkException {
        return this.certificateStorage.getCertificatesByOwnerID(userID);
    }

    public Collection<ASAPCertificate> getCertificateBySigner(CharSequence userID) throws SharkException {
        return this.certificateStorage.getCertificatesBySignerID(userID);
    }

    public CharSequence getOwnerName() {
        return this.certificateStorage.getOwnerName();
    }

    @Override
    public int getSigningFailureRate(CharSequence personID)  {
        if(personID.toString().equalsIgnoreCase(this.getOwnerID().toString())) {
            return OtherPerson.YOUR_SIGNING_FAILURE_RATE;
        }

        try {
            return this.getPersonValues(personID).getSigningFailureRate();
        } catch (SharkException e) {
            // fix that problem by assuming worst failure rate
            return OtherPerson.WORST_SIGNING_FAILURE_RATE;
        }
    }

    public void setSigningFailureRate(CharSequence personID, int failureRate) throws SharkException {
        if(failureRate < OtherPerson.BEST_SIGNING_FAILURE_RATE
                || failureRate > OtherPerson.WORST_SIGNING_FAILURE_RATE)
            throw new SharkCryptoException("failure rate you are trying to set is out of defined range");

        this.getPersonValues(personID).setSigningFailureRate(failureRate);
        this.certificateStorage.syncIdentityAssurance();
    }
}
