package net.sharksystem.asap.persons;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPEncounterConnectionType;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateImpl;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.CredentialMessageInMemo;
import net.sharksystem.asap.utils.DateTimeHelper;
import net.sharksystem.fs.ExtraData;
import net.sharksystem.pki.CredentialMessage;
import net.sharksystem.pki.PKIHelper;
import net.sharksystem.utils.Log;

import java.io.*;
import java.security.*;
import java.util.*;

/**
 * This class adds person management to certificate management. Certificate Storage is a separate
 * object. Person information are managed with this class. They can be seen as index of
 * certificates.
 */
public class PersonStoreImplAndCertsWrapper implements PersonInformationStore {
    private static final CharSequence ASAP_PERSONS_STORAGE_MEMENTO_KEY = "asapPersonsInfoMemento";
    protected final ASAPCertificateStorage certificateStorage;
    private final net.sharksystem.asap.crypto.ASAPKeyStore asapKeyStorage;

    // keep other persons - contact list in other words
    private List<PersonValuesImpl> personsList = new ArrayList<>();

    private ASAPCertificateStorage getCertsStorage() {
        return this.certificateStorage;
    }

    private ASAPKeyStore getASAPKeyStore() {
        return this.asapKeyStorage;
    }

    public PersonStoreImplAndCertsWrapper(ASAPCertificateStorage certificateStorage, net.sharksystem.asap.crypto.ASAPKeyStore asapKeyStorage) {

        this.certificateStorage = certificateStorage;
        this.asapKeyStorage = asapKeyStorage;

        long creationTime = DateTimeHelper.TIME_NOT_SET;
        try {
            creationTime = this.asapKeyStorage.getKeysCreationTime();
        } catch (ASAPSecurityException e) {
            Log.writeLog(this, "creation time not set. No keypair so far?! : "
                    + e.getLocalizedMessage());
        }

        boolean createNewPair = false;
        if(creationTime == DateTimeHelper.TIME_NOT_SET) {
            createNewPair = true;
        } else {
            // check expiration time
            Calendar createCal = ASAPCertificateImpl.long2Calendar(creationTime);
            createCal.add(Calendar.YEAR, ASAPCertificate.DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS);
            if (createCal.getTimeInMillis() < System.currentTimeMillis()) {
                Log.writeLog(this, "local key pair expired - reset");
                createNewPair = true;
            }
        }

        if(createNewPair) {
            try {
                this.asapKeyStorage.generateKeyPair();
            } catch (ASAPSecurityException e) {
                Log.writeLog(this, "failure receiving keys: " + e.getLocalizedMessage());
            }
        }
    }

    public PublicKey getPublicKey() throws ASAPSecurityException {
        return this.asapKeyStorage.getPublicKey();
    }

    public PublicKey getPublicKey(CharSequence peerID) throws SharkException {
        return this.certificateStorage.getPublicKey(peerID);
    }

    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        return this.asapKeyStorage.getPrivateKey();
    }

    public long getKeysCreationTime() throws ASAPSecurityException {
        return this.asapKeyStorage.getKeysCreationTime();
    }


    public void generateKeyPair() throws ASAPSecurityException {
        this.asapKeyStorage.generateKeyPair();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //                           other persons management - in memory                           //
    //////////////////////////////////////////////////////////////////////////////////////////////

    public PersonValuesImpl getPersonValues(CharSequence userID) throws ASAPSecurityException {
        for (PersonValuesImpl personValues : this.personsList) {
            if (personValues.getUserID().toString().equalsIgnoreCase(userID.toString())) {
                return personValues;
            }
        }

        throw new ASAPSecurityException("person not found with userID: " + userID);
    }

    public PersonValuesImpl getPersonValuesByPosition(int position) throws ASAPSecurityException {
        try {
            PersonValuesImpl personValues = this.personsList.get(position);
            return personValues;
        } catch (IndexOutOfBoundsException e) {
            throw new ASAPSecurityException("position too high: " + position);
        }
    }

    @Override
    public PersonValues getPersonValuesByID(CharSequence personID) throws ASAPSecurityException {
        // TODO: a map would be better?
        String wantedIDString = personID.toString();
        for(PersonValuesImpl personValues : this.personsList) {
            if(wantedIDString.equalsIgnoreCase(personValues.getUserID().toString())) {
                return personValues;
            }
        }

        throw new ASAPSecurityException("no person with this id found: " + personID);
    }

    public boolean isMe(CharSequence userID) {
        return this.getOwnerID().equals(userID);
    }

    public int getNumberOfPersons() {
        return this.personsList.size();
    }

    public int getIdentityAssurance(CharSequence peerID) throws ASAPSecurityException {
        // It is us - we believe in ourselves
        if(this.isMe(peerID)) return OtherPerson.HIGHEST_IDENTITY_ASSURANCE_LEVEL;

        try {
            return this.getCertsStorage().getIdentityAssurances(peerID, this.getASAPKeyStore(), this);
//            return this.getPersonValues(peerID).getIdentityAssurance();
        }
        catch(ASAPSecurityException e) {
            // not found - complete unreliable
            return OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL;
        }
    }


    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID)
            throws ASAPSecurityException {

        return this.certificateStorage.getIdentityAssurancesCertificationPath(userID, this.getASAPKeyStore(), this);
    }

    public CharSequence getOwnerID() {
        return this.certificateStorage.getOwnerID();
    }

    protected String getPersonsListAsString() {
        if(this.personsList == null) return "no personsList object (null)";
        StringBuilder sb = new StringBuilder();
        sb.append("personsList object#"); sb.append(this.personsList);sb.append(" ");
        if(this.personsList.isEmpty()) {
            sb.append("is empty");
            return sb.toString();
        } else {
            sb.append(this.personsList.size()); sb.append(" entries:\n");
        }

        int i = 0;
        boolean first = true;
        for(PersonValuesImpl personValues : this.personsList) {
            if(first) first = false; else sb.append(", ");
            sb.append(i++); sb.append(": "); sb.append(PKIHelper.personalValue2String(personValues));
            sb.append("\n");
        }
        return sb.toString();
    }

    //@Override
    public ASAPCertificate addAndSignPerson(
            CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince,
            ASAPEncounterConnectionType encounterType)
            throws ASAPSecurityException, IOException {

        Log.writeLog(this, "entered addAndSignPerson");
        // try to overwrite owner ?
        if (userID.toString().equalsIgnoreCase(this.getOwnerID().toString())) {
            throw new ASAPSecurityException("cannot add person with your userID");
        }

        // already in there
        boolean personAlreadyExists = false;
        for (PersonValuesImpl personValues : this.personsList) {
            if (userID.toString().equalsIgnoreCase(personValues.getUserID().toString())) {
                //throw new SharkCryptoException("person with userID already exists: " + userID);
                personAlreadyExists = true;
                break;
            }
        }

        if(!personAlreadyExists) {
            Log.writeLog(this, "going to add person " + userID + " | " + userName);
            // ok - add
            PersonValuesImpl newPersonValues =
                    new PersonValuesImpl(userID, userName, this.certificateStorage, this);
            this.personsList.add(newPersonValues);
            this.save();
            ////////////////////// debug
            /*
            Log.writeLog(this, "personsList " + this.personsList);
            Log.writeLog(this, "personsList " + this.getPersonsListAsString());
             */
            ////////////////////// debug

        } else {
            Log.writeLog(this, "person already exists - don't change anything");
        }

        // is there already a certificate?
        try {
            Log.writeLog(this, "check for duplicated certificates");
            Collection<ASAPCertificate> certificates = this.getCertificatesBySubject(userID);
            for (ASAPCertificate certTemp : certificates) {
                if (certTemp.getIssuerID().toString().equalsIgnoreCase(this.getOwnerID().toString())) {
                    // drop it
                    Log.writeLog(this, "duplicate found - drop");
                    this.certificateStorage.removeCertificate(certTemp);
                }
            }
        } catch (ASAPSecurityException e) {
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
                    this.asapKeyStorage.getAsymmetricSigningAlgorithm(),
                    encounterType);

            // make it persistent
            Log.writeLog(this, "store certificate");
            this.certificateStorage.storeCertificate(cert);

            return cert;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.writeLogErr(this, "cannot create certificate: " + e.getLocalizedMessage());
            e.printStackTrace();
            throw new ASAPSecurityException("cannot create certificate: " + e.getLocalizedMessage());
        }
    }

    @Override
    public void addCertificate(ASAPCertificate asapCert) throws IOException, ASAPSecurityException {
        PersonValuesImpl newPersonValues =
                new PersonValuesImpl(asapCert.getSubjectID(), asapCert.getSubjectName(),
                        this.certificateStorage, this);

        this.personsList.add(newPersonValues);

        this.certificateStorage.storeCertificate(asapCert);
    }

    @Override
    public boolean incorporateReceivedCertificates() {
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
                } catch (ASAPSecurityException e) {
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

    public Collection<ASAPCertificate> getCertificatesBySubject(CharSequence userID) throws ASAPSecurityException {
        return this.certificateStorage.getCertificatesBySubjectID(userID);
    }

    public Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence userID) throws ASAPSecurityException {
        return this.certificateStorage.getCertificatesByIssuerID(userID);
    }

    public Collection<ASAPCertificate> getCertificatesForOwnerSubject(CharSequence userID) throws ASAPSecurityException {
        return this.certificateStorage.getCertificatesForOwnerSubject();
    }

    public ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID)
            throws ASAPSecurityException {

        return this.certificateStorage.getCertificateByIssuerAndSubjectID(issuerID, subjectID);
    }


    public Set<ASAPCertificate> getAllCertificates() {
        return this.certificateStorage.getAllCertificates();
    }

    public boolean verifyCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException {
        try {
            return asapCertificate.verify(this.getPublicKey());
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new ASAPSecurityException(e.getClass().getSimpleName() + ": " + e.getLocalizedMessage());
        }
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
        } catch (ASAPSecurityException e) {
            // fix that problem by assuming worst failure rate
            return OtherPerson.WORST_SIGNING_FAILURE_RATE;
        }
    }

    public void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException {
        if (failureRate < OtherPerson.BEST_SIGNING_FAILURE_RATE
                || failureRate > OtherPerson.WORST_SIGNING_FAILURE_RATE)
            throw new ASAPSecurityException("failure rate you are trying to set is out of defined range: "
            + OtherPerson.WORST_SIGNING_FAILURE_RATE + " <= failureRate <= " + OtherPerson.BEST_SIGNING_FAILURE_RATE);

        this.getPersonValues(personID).setSigningFailureRate(failureRate);
        this.certificateStorage.syncIdentityAssurance();
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             credentials                                                    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public CredentialMessage createCredentialMessage()
            throws ASAPSecurityException {

        CredentialMessageInMemo credentialMessage = new CredentialMessageInMemo(
                this.getOwnerID(), this.getOwnerName(), this.getKeysCreationTime(), this.getPublicKey());

        return credentialMessage;
    }


    @Override
    public CredentialMessage createCredentialMessage(byte[] extraData) throws ASAPSecurityException {
        CredentialMessageInMemo credentialMessage = new CredentialMessageInMemo(
                this.getOwnerID(), this.getOwnerName(), this.getKeysCreationTime(), this.getPublicKey(), extraData);

        return credentialMessage;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             persistence                                                    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private ExtraData mementoExtraData;

    public void setMementoTarget(ExtraData extraData) {
        this.mementoExtraData = extraData;
        try {
            byte[] memento = this.mementoExtraData.getExtra(ASAP_PERSONS_STORAGE_MEMENTO_KEY);
            this.restoreMemento(memento);
        } catch (IOException | SharkException e) {
            // no memento - okay
        }
    }

    public void save() {
        if(this.mementoExtraData != null) {
            try {
                this.mementoExtraData.putExtra(ASAP_PERSONS_STORAGE_MEMENTO_KEY, this.getMemento());
            } catch (IOException | SharkException e) {
                Log.writeLogErr(this, "cannot write memento: " + e.getLocalizedMessage());
            }
        } else {
            Log.writeLog(this, "cannot write data - no persistent storage");
        }

    }

    private void restoreMemento(byte[] memento) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(memento);
        this.restoreFromStream(bais);
    }

    private byte[] getMemento() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.savetoStream(baos);
        return baos.toByteArray();
    }

    public void savetoStream(OutputStream os) throws IOException {
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

    public void restoreFromStream(InputStream is) throws IOException {
        if(is == null) throw new IOException("cannot read from null stream");

        DataInputStream dis = new DataInputStream(is);
        int size = dis.readInt();
        this.personsList = new ArrayList<>();
        while(size-- > 0) {
            this.personsList.add(new PersonValuesImpl(dis, this.certificateStorage, this));
        }
    }
}
