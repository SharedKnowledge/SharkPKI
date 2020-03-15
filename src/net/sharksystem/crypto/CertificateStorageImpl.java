package net.sharksystem.crypto;

import net.sharksystem.asap.ASAP;
import net.sharksystem.asap.util.Log;
import net.sharksystem.persons.OtherPerson;
import net.sharksystem.persons.PersonsStorage;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.*;

public abstract class CertificateStorageImpl implements ASAPCertificateStorage {
    private final CharSequence ownerID;
    private final CharSequence ownerName;

    private Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap = null;

    public CertificateStorageImpl(CharSequence ownerID, CharSequence ownerName) {
        this.ownerID = ownerID;
        this.ownerName = ownerName;
    }

    @Override
    public CharSequence getOwnerID() {
        return this.ownerID;
    }

    @Override
    public CharSequence getOwnerName() {
        return this.ownerName;
    }

    boolean isExpired(ASAPCertificate cert) {
        return System.currentTimeMillis() > cert.getValidUntil().getTimeInMillis();
    }

    public void syncIdentityAssurance() {
        this.userIdentityAssurance = null;
    }

    public void syncCertificates() {
        this.certificatesByOwnerIDMap = null;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       getter on certificate map                                         //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public Collection<ASAPCertificate> getCertificatesBySubjectID(CharSequence userID) {
        if(this.certificatesByOwnerIDMap == null) {
            this.certificatesByOwnerIDMap = new HashMap<>();
            this.readCertificatesFromStorage(this.certificatesByOwnerIDMap);
        }

        Set<ASAPCertificate> asapCertificates = this.certificatesByOwnerIDMap.get(userID);
        if(asapCertificates == null) {
            asapCertificates = new HashSet<>();
        }
        return asapCertificates;
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesForOwnerSubject() {
        return this.getCertificatesBySubjectID(this.getOwnerID());
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesByIssuerID(CharSequence userID) {
        Set<ASAPCertificate> certSetIssuer = new HashSet<>();
        for(Set<ASAPCertificate> certSet : this.certificatesByOwnerIDMap.values()) {
            for(ASAPCertificate cert : certSet) {
                if(cert.getIssuerID().toString().equalsIgnoreCase(userID.toString())) {
                    certSetIssuer.add(cert);
                }
            }
        }

        return certSetIssuer;
    }

    public Collection<ASAPCertificate> getCertificatesSinceEra(int sinceEra) {
        // sync with external changes
        this.readReceivedCertificates(this.certificatesByOwnerIDMap, sinceEra);
        // create a set of all eras after since era including since era
        Set<Integer> eraSpace = new HashSet<>();

        // iterate
        int currentEra = sinceEra;
        int nextEra = sinceEra;
        do {
            currentEra = nextEra; // does nothing in first loop
            eraSpace.add(currentEra);
            nextEra = ASAP.nextEra(currentEra);
        } while(currentEra != this.getEra());

        Set<ASAPCertificate> certSetEra = new HashSet<>();
        for(Set<ASAPCertificate> certSet : this.certificatesByOwnerIDMap.values()) {
            for(ASAPCertificate cert : certSet) {
                if(eraSpace.contains(cert.getASAPStorageAddress().getEra())) {
                    // contains? Integer object or Integer value used?
                    certSetEra.add(cert);
                }
            }
        }

        return certSetEra;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             data management                                             //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void removeCertificate(ASAPCertificate cert2remove) throws IOException {
        List<ASAPCertificate> certs2remove = new ArrayList<>();
        certs2remove.add(cert2remove);
        this.removeCertificate(certs2remove);
    }

    public void removeCertificate(Collection<ASAPCertificate> certs2remove) throws IOException {
        // drop caches
        this.certificatesByOwnerIDMap = null;
        this.userIdentityAssurance = null;

        try {
            this.removeCertificatesFromStorage(certs2remove);
        } catch (IOException e) {
            Log.writeLog(this, "cannot remove certificate: " + e.getLocalizedMessage());
        }
    }

    @Override
    public ASAPStorageAddress storeCertificate(ASAPCertificate asapCertificate) throws IOException {
        // drop cache
        this.certificatesByOwnerIDMap = null;
        this.userIdentityAssurance = null;

        return storeCertificateInStorage(asapCertificate);
    }

    protected abstract ASAPStorageAddress storeCertificateInStorage(ASAPCertificate cert2store)
            throws IOException;

    protected void removeCertificatesFromStorage(Collection<ASAPCertificate> certs2remove) throws IOException {
        if(certs2remove == null) return;

        for(ASAPCertificate cert2remove : certs2remove) {
            this.removeCertificateFromStorage(cert2remove);
        }
    }

    protected abstract void removeCertificateFromStorage(ASAPCertificate cert2remove) throws IOException;

    protected abstract void readCertificatesFromStorage(Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap);

    protected abstract void readReceivedCertificates(
            Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap, int sinceEra);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            identity assurance                                            //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private class IdentityAssurance {
        private int value = -1;
        final List<CharSequence> path;
        float floatValue;

        IdentityAssurance(int value, List<CharSequence> path) {
            this.value = value;
            this.path = path;
        }

        IdentityAssurance(float floatValue, List<CharSequence> path) {
            this.floatValue = floatValue;
            this.path = path;
        }

        int getValue() {
            if(this.value < 0) {
                if(this.floatValue >= 0) {
                    // scale, round and return
                    float identityAssuranceFloat = this.floatValue;
                    identityAssuranceFloat *= 10; //scale
                    this.value = (int) identityAssuranceFloat; // cut
                    if( (identityAssuranceFloat - this.value) >= 0.5) {
                        this.value++; // round
                    };
                }
            }

            return this.value;
        }
    }

    private IdentityAssurance worstIdentityAssurance =
            new IdentityAssurance(OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL, new ArrayList<>());

    private Map<CharSequence, IdentityAssurance> userIdentityAssurance; // cache

    private boolean verify(ASAPCertificate cert, PublicKey publicKey) {
        if(cert == null) return false;

        try {
            if(cert.verify(publicKey)) {
                return true;
            }

            Log.writeLogErr(this,"cannot verify stored certificate - that's serious");
            Log.writeLog(this,"cannot verify stored certificate - maybe delete??!!");

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.writeLogErr(this,"cannot verify stored certificate: " + e.getLocalizedMessage());
        }

        return false;
    }

    private IdentityAssurance getIdentityAssurance(CharSequence userID, PersonsStorage personsStorage)
            throws SharkCryptoException {
        // general setup?
        if(this.userIdentityAssurance == null) {
            this.userIdentityAssurance = new HashMap<CharSequence, IdentityAssurance>();
            this.setupIdentityAssurance(userID, personsStorage);
        }

        IdentityAssurance identityAssurance = this.userIdentityAssurance.get(userID);
        // setup individual user?
        if(identityAssurance == null) {
            // setup
            this.setupIdentityAssurance(userID, personsStorage);
            // try again
            identityAssurance = this.userIdentityAssurance.get(userID);
        }

        return identityAssurance;
    }

    @Override
    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID, PersonsStorage personsStorage)
            throws SharkCryptoException {
        return this.getIdentityAssurance(userID, personsStorage).path;
    }

    public int getIdentityAssurances(CharSequence userID, PersonsStorage personsStorage) throws SharkCryptoException {
        return this.getIdentityAssurance(userID, personsStorage).getValue();
    }

    private void setupIdentityAssurance(CharSequence userID, PersonsStorage personsStorage) throws SharkCryptoException {
        Collection<ASAPCertificate> certificates = this.getCertificatesBySubjectID(userID);
        if (certificates == null || certificates.isEmpty()) {
            // we don't know anything about this person
            this.userIdentityAssurance.put(userID, this.worstIdentityAssurance);
            return;
        }
        else {
            // do we have a certificate signed by owner?
            boolean found = false;
            for(ASAPCertificate certificate : certificates) {
                if (certificate.getIssuerID().toString().equalsIgnoreCase(this.ownerID.toString())) {
                    // verify certificate
                    found = true;
                    try {
                        if(certificate.verify(personsStorage.getPublicKey())) {
                            ArrayList<CharSequence> directPath = new ArrayList<>();
                            directPath.add(this.ownerID);
                            this.userIdentityAssurance.put(userID,
                                    new IdentityAssurance(OtherPerson.HIGHEST_IDENTITY_ASSURANCE_LEVEL, directPath));

                            return; // there is only one direct certificate
                        }
                    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                        Log.writeLogErr(this, "cannot verify a direct certificate - remove it: "
                                + e.getLocalizedMessage());
                        try {
                            this.removeCertificate(certificate);
                        } catch (IOException ex) {
                            Log.writeLog(this, "cannot remove certificate: " + ex.getLocalizedMessage());
                        }
                    }
                }
            }
            if(found) {
                throw new SharkCryptoException
                        ("there is a certificate signed by owner but cannot be verified - that's serious");
            }
        }

        IdentityAssurance bestIa = null;

        // no direct cert from owner:
        // iterate again
        for(ASAPCertificate certificate : certificates) {
            // we have certificates but nothing issued by owner - we look for a certificated way from owner to userID

            // find a path and calculate best failure rate of it
            IdentityAssurance tmpIa = this.calculateIdentityProbability(new ArrayList<>(), // init chain
                    userID, certificate, -1, personsStorage);

            if(bestIa == null) bestIa = tmpIa; // first round
            else {
                bestIa = bestIa.floatValue < tmpIa.floatValue ? // tmp is more likely than best - switch
                        tmpIa : bestIa;
            }
        }

        this.userIdentityAssurance.put(userID, bestIa);
    }

    /**
     * Follow chain backward. If it reaches owner.. there will be an assurance level better than
     * worst. If it does not end at owner or even goes in circles - it worst level.
     *
     * @param idPath                     already visited ids
     * @param currentPersonID             current id
     * @param accumulatedIdentityProbability current failure rate so far (value between 0 and 1)
     * @return what we lool for:
     * YOU - Person A - Person B - ...- current Person - ... - Person in question
     * <p>
     * We go backward in chain to - hopefully reach you
     */
    private IdentityAssurance calculateIdentityProbability(
            List<CharSequence> idPath, CharSequence currentPersonID,
            ASAPCertificate currentCertificate, float accumulatedIdentityProbability,
            PersonsStorage personsStorage)
    {
        // are we in a circle?
        if (idPath.contains(currentPersonID)) return this.worstIdentityAssurance; // escape circle

        // remember this step
        idPath.add(currentPersonID);

        // if we have a certificate that is signed by app owner - we are done here.
        if (currentCertificate.getIssuerID().toString().equalsIgnoreCase(this.ownerID.toString())) {
            // we should be able to verify currentCertificate with owners public key
            PublicKey publicKey = null;
            try {
                publicKey = personsStorage.getPublicKey();
                if(!this.verify(currentCertificate, publicKey)) {
                    return this.worstIdentityAssurance;
                }
            } catch (SharkCryptoException e) {
                return this.worstIdentityAssurance; // no key at all
            }

            // could be verified
            if(accumulatedIdentityProbability < 0) {
                // not yet set
                return new IdentityAssurance(0, idPath); // not yet set
            } else {
                return new IdentityAssurance(accumulatedIdentityProbability, idPath);
            }
        }

        // not finished

        // is there a next step towards owner? Yes, if there is a certificate owner by the current signer
        CharSequence proceedingPersonID = currentCertificate.getIssuerID();
        Collection<ASAPCertificate> proceedingCertificates =
                this.getCertificatesBySubjectID(proceedingPersonID);

        if(proceedingCertificates == null || proceedingCertificates.isEmpty())
            // no certificate - cannot verify current certificate.
            return this.worstIdentityAssurance;

        // next step in depth-first search
        IdentityAssurance bestIa = null;
        for(ASAPCertificate proceedingCertificate : proceedingCertificates) {
            // we must be able to verify current certificate (if any)
            if(!this.verify(currentCertificate, proceedingCertificate.getPublicKey())) continue;

            // make a idPath copy
            List<CharSequence> copyIDPath = new ArrayList<>();
            copyIDPath.addAll(idPath);

            // convert failure rate number to failure probability something between 0 and 1.
            float failureProbability = ((float) personsStorage.getSigningFailureRate(proceedingPersonID)) / 10;

            // OK. We have information about this person. Calculate assuranceLevel
            /*
            Only the owner is expected to make no failure when signing certificates. (That's an illusion but
            we take it.) Any other person makes failure and associates public key with the wrong person.

            The probability of doing so is failureProbability.

            We have a chain of signers here. Each has signed a certificate of an owner who is signer in the
            next step. Failure accumulate. Assuming four steps. O - A - B - C. O is the owner. O has met A. We assume
            a failureProb of 0 (it is the owner). O has set a failure prob for A (e.g. pA = 30% = 0,3).

            70% (0,7) of As' certificates are presumably right, 30% (0,3 wrong). A has also signed a certificate for
            B. That certificate is right with 70% (0,7). Now, B has also signed a certificate for C and als B makes
            failure, let's assume 40% (0,4). Thus, 60% are right.

            How does it look from Owners perspective? O wants to know how sure it can be of Cs' identity.
            It can calculate beginning from the end of the chain: 60% of certificates signed by B are right.
            6 out of 10  are right. 4 out of 10 are wrong.
            O cannot verify Bs' certificate, though. It only has certificate from A. With a probability of 30%,
            A has signed a wrong certificate for B. O can calculate. Nearly any third certificate signed by A is
            wrong. Statistically, a third of those right 6 certificates of B are wrong due to A. O can say:

            4 out of 10 certificates in that signing queue are falsified. O can be sure of Cs' identity with 60%.

            identityAssurance(C) = (1-failure(C) * (1-failure(B))
             */
            if (accumulatedIdentityProbability < 0) {
                // haven't yet calculated any assurance prob. Set initial value
                accumulatedIdentityProbability = 1 - failureProbability;
            } else {
                accumulatedIdentityProbability *= (1 - failureProbability);
            }

            IdentityAssurance tmpIa = this.calculateIdentityProbability(copyIDPath,
                    proceedingCertificate.getSubjectID(),
                    proceedingCertificate,
                    accumulatedIdentityProbability,
                    personsStorage);

            if(bestIa == null) bestIa = tmpIa;
            else {
                bestIa = bestIa.floatValue < tmpIa.floatValue ? // tmp is more likely than best - switch
                        tmpIa : bestIa;
            }
        }

        return bestIa;
    }

    public ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException {
        return new ASAPStorageAddressImpl(serializedAddress);
    }

    protected class ASAPStorageAddressImpl implements ASAPStorageAddress {
        private final int era;
        private final CharSequence uri;
        private final CharSequence format;

        ASAPStorageAddressImpl(CharSequence format, CharSequence uri, int era) {
            this.format = format;
            this.uri = uri;
            this.era = era;
        }

        ASAPStorageAddressImpl(int era) {
            this(ASAPCertificateStorage.APP_NAME, ASAPCertificate.ASAP_CERTIFICATE_URI, era);
        }

        ASAPStorageAddressImpl(byte[] serialized) throws IOException {
            ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
            DataInputStream dais = new DataInputStream(bais);

            this.format = dais.readUTF();
            this.uri = dais.readUTF();
            this.era = dais.readInt();
        }

        public byte[] asBytes() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream daos = new DataOutputStream(baos);

            try {
                daos.writeUTF(this.format.toString());
                daos.writeUTF(this.uri.toString());
                daos.writeInt(this.era);
                return baos.toByteArray();
            } catch (IOException e) {
                // this cannot happen with a byte array stream
                return null;
            }
        }

        @Override
        public CharSequence getFormat() {
            return this.format;
        }

        @Override
        public CharSequence getUri() {
            return this.uri;
        }

        @Override
        public int getEra() {
            return this.era;
        }
    }
}
