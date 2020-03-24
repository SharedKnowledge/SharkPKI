package net.sharksystem.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPEngine;
import net.sharksystem.asap.MultiASAPEngineFS;
import net.sharksystem.asap.apps.ASAPMessages;
import net.sharksystem.asap.util.Log;
import net.sharksystem.crypto.*;

import java.io.*;
import java.security.*;
import java.util.*;

import static net.sharksystem.crypto.ASAPCertificateImpl.DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS;
import static net.sharksystem.crypto.ASAPCertificateImpl.DEFAULT_SIGNATURE_METHOD;

public class PersonsStorageImpl implements PersonsStorage {
    private final ASAPCertificateStorage certificateStorage;
    private final ASAPKeyStorage asapKeyStorage;
    private final String signingAlgorithm;

    // keep other persons - contact list in other words
    private List<PersonValuesImpl> personsList = new ArrayList<>();

    public PersonsStorageImpl(ASAPCertificateStorage certificateStorage) throws SharkException {
        this(certificateStorage, new InMemoASAPKeyStorage(), DEFAULT_SIGNATURE_METHOD);
    }

    public PersonsStorageImpl(ASAPCertificateStorage certificateStorage,
                              ASAPKeyStorage asapKeyStorage, String signingAlgorithm) throws SharkException {
        this.certificateStorage = certificateStorage;
        this.asapKeyStorage = asapKeyStorage;
        this.signingAlgorithm = signingAlgorithm;

        Calendar createCal = null;
        try {
            long creationTime = this.asapKeyStorage.getCreationTime(); // throws exception if not set

            // check expiration time
            createCal = ASAPCertificateImpl.long2Calendar(creationTime);
            createCal.add(Calendar.YEAR, DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS);
            if (createCal.getTimeInMillis() > System.currentTimeMillis()) {
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

    public long getKeysCreationTime() throws SharkCryptoException {
        return this.asapKeyStorage.getCreationTime();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                           other persons management - in memory                           //
    //////////////////////////////////////////////////////////////////////////////////////////////

    public PersonValuesImpl getPersonValues(CharSequence userID) throws SharkException {
        for (PersonValuesImpl personValues : this.personsList) {
            if (personValues.getUserID().toString().equalsIgnoreCase(userID.toString())) {
                return personValues;
            }
        }

        throw new SharkException("person not found with userID: " + userID);
    }

    public PersonValuesImpl getPersonValuesByPosition(int position) throws SharkException {
        try {
            PersonValuesImpl personValues = this.personsList.get(position);
            return personValues;
        } catch (IndexOutOfBoundsException e) {
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
    public ASAPCertificate addAndSignPerson(
            CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince)
            throws SharkCryptoException, IOException {

        Log.writeLog(this, "entered addAndSignPerson");
        // try to overwrite owner ?
        if (userID.toString().equalsIgnoreCase(this.getOwnerID().toString())) {
            throw new SharkCryptoException("cannot add person with your userID");
        }

        // already in there
        for (PersonValuesImpl personValues : this.personsList) {
            if (userID.toString().equalsIgnoreCase(personValues.getUserID().toString())) {
                throw new SharkCryptoException("person with userID already exists: " + userID);
            }
        }

        Log.writeLog(this, "going to add");
        // ok - add
        PersonValuesImpl newPersonValues =
                new PersonValuesImpl(userID, userName, this.certificateStorage, this);
        this.personsList.add(newPersonValues);

        // is there already a certificate?
        try {
            Log.writeLog(this, "check for duplicated certificates");
            Collection<ASAPCertificate> certificates = this.getCertificateBySubject(userID);
            for (ASAPCertificate certTemp : certificates) {
                if (certTemp.getIssuerID().toString().equalsIgnoreCase(this.getOwnerID().toString())) {
                    // drop it
                    Log.writeLog(this, "duplicate found - drop");
                    this.certificateStorage.removeCertificate(certTemp);
                }
            }
        } catch (SharkException e) {
            e.printStackTrace();
        }

        ASAPCertificate cert = null;
        try {
            Log.writeLog(this, "produce new certificate");
            cert = ASAPCertificateImpl.produceCertificate(
                    this.getOwnerID(),
                    this.getOwnerName(),
                    this.getPrivateKey(),
                    userID,
                    userName,
                    publicKey,
                    validSince,
                    this.signingAlgorithm);

            // make it persistent
            Log.writeLog(this, "store certificate");
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
                new PersonValuesImpl(asapCert.getSubjectID(), asapCert.getSubjectName(),
                        this.certificateStorage, this);

        this.personsList.add(newPersonValues);

        this.certificateStorage.storeCertificate(asapCert);
    }

    @Override
    public boolean syncNewReceivedCertificates() {
        Log.writeLog(this, "sync with received certificates");
        Collection<ASAPCertificate> newReceivedCertificates = this.certificateStorage.getNewReceivedCertificates();

        if(newReceivedCertificates != null)
            Log.writeLog(this, "#received certificates == " + newReceivedCertificates.size());

        boolean changed = false;
        // check whether to add a new person
        for(ASAPCertificate newCert : newReceivedCertificates) {
            if(!newCert.getSubjectID().toString().equalsIgnoreCase(this.getOwnerID().toString())) {
                // a new cert received
                Log.writeLog(this, "read new cert");

                // user already exists
                try {
                    this.getPersonValues(newCert.getSubjectID());
                    Log.writeLog(this, "user id already exists: " + newCert.getSubjectID());
                } catch (SharkException e) {
                    // not found - what we look for
                    PersonValuesImpl newPersonValues =
                            new PersonValuesImpl(newCert.getSubjectID(), newCert.getSubjectName(),
                                    this.certificateStorage, this);

                    this.personsList.add(newPersonValues);
                    changed = true;
                }
            } else {
                Log.writeLog(this, "received certificate has owner as subject - nothing added");
            }
        }

        return changed;
    }

    public Collection<ASAPCertificate> getCertificateBySubject(CharSequence userID) throws SharkException {
        return this.certificateStorage.getCertificatesBySubjectID(userID);
    }

    public Collection<ASAPCertificate> getCertificateByIssuer(CharSequence userID) throws SharkException {
        return this.certificateStorage.getCertificatesByIssuerID(userID);
    }

    public Collection<ASAPCertificate> getCertificatesForOwnerSubject(CharSequence userID) throws SharkException {
        return this.certificateStorage.getCertificatesForOwnerSubject();
    }

    public CharSequence getOwnerName() {
        return this.certificateStorage.getOwnerName();
    }

    @Override
    public int getSigningFailureRate(CharSequence personID) {
        if (personID.toString().equalsIgnoreCase(this.getOwnerID().toString())) {
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
        if (failureRate < OtherPerson.BEST_SIGNING_FAILURE_RATE
                || failureRate > OtherPerson.WORST_SIGNING_FAILURE_RATE)
            throw new SharkCryptoException("failure rate you are trying to set is out of defined range");

        this.getPersonValues(personID).setSigningFailureRate(failureRate);
        this.certificateStorage.syncIdentityAssurance();
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             credentials                                                    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public CredentialMessage createCredentialMessage()
            throws SharkCryptoException {

        CredentialMessage credentialMessage = new CredentialMessage(
                this.getOwnerID(), this.getOwnerName(), this.getKeysCreationTime(), this.getPublicKey());

        return credentialMessage;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             persistence                                                    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * called from person values
     */
    void save() {
        // nothing - should be overwritten
        Log.writeLog(this, "save() schould be overwritten by inheriting classes");
    }

    @Override
    public void store(OutputStream os) throws IOException {
        if(os == null) throw new IOException("cannot write in null stream");
        if(this.personsList == null || this.personsList.isEmpty()) {
            Log.writeLog(this, "person list is empty - nothing to store");
            return;
        }

        DataOutputStream dos = new DataOutputStream(os);

        dos.writeInt(this.personsList.size()); // number of contacts

        // write each contact
        for(PersonValuesImpl personValues : this.personsList) {
            personValues.writePersonValues(dos);
        }
    }

    @Override
    public void load(InputStream is) throws IOException {
        if(is == null) throw new IOException("cannot read from null stream");

        DataInputStream dis = new DataInputStream(is);
        int size = dis.readInt();
        this.personsList = new ArrayList<>();
        while(size-- > 0) {
            this.personsList.add(new PersonValuesImpl(dis, this.certificateStorage, this));
        }
    }
}
