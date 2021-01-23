package net.sharksystem.asap.crypto;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.util.Log;
import net.sharksystem.asap.persons.OtherPerson;
import net.sharksystem.asap.persons.ASAPCertificateStore;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.*;

public abstract class AbstractCertificateStore implements ASAPCertificateStorage {
    private final CharSequence ownerID;
    private final CharSequence ownerName;

    private Map<CharSequence, Set<ASAPCertificate>> certificatesBySubjectIDMap = null;

    public AbstractCertificateStore(CharSequence ownerID, CharSequence ownerName) {
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
        this.certificatesBySubjectIDMap = null;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       getter on certificate map                                         //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private void checkCertificatesBySubjectIDMap() {
        if(this.certificatesBySubjectIDMap == null) {
            this.certificatesBySubjectIDMap = new HashMap<>();
            this.readCertificatesFromStorage(this.certificatesBySubjectIDMap);
        }
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesBySubjectID(CharSequence subjectID) {
        this.checkCertificatesBySubjectIDMap();
        Set<ASAPCertificate> asapCertificates = this.certificatesBySubjectIDMap.get(subjectID);
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
    public Collection<ASAPCertificate> getCertificatesByIssuerID(CharSequence issuerID) {
        this.checkCertificatesBySubjectIDMap();
        Set<ASAPCertificate> certSetIssuer = new HashSet<>();
        for(Set<ASAPCertificate> certSet : this.certificatesBySubjectIDMap.values()) {
            for(ASAPCertificate cert : certSet) {
                if(cert.getIssuerID().toString().equalsIgnoreCase(issuerID.toString())) {
                    certSetIssuer.add(cert);
                }
            }
        }

        return certSetIssuer;
    }

    public ASAPCertificate getCertificateByIssuerAndSubjectID(
            CharSequence issuerID, CharSequence subjectID) throws ASAPSecurityException {

        Collection<ASAPCertificate> certificateBySubject = this.getCertificatesBySubjectID(subjectID);

        if(certificateBySubject == null || certificateBySubject.size() < 1) {
            throw new ASAPSecurityException("no certificate found");
        }

        for(ASAPCertificate c : certificateBySubject) {
            if(c.getIssuerID().equals(issuerID)) {
                // got it
                return c;
            }
        }

        throw new ASAPSecurityException("no certificate found");
    }


    public Collection<ASAPCertificate> getNewReceivedCertificates() {
        // sync with external changes
        this.checkCertificatesBySubjectIDMap();

        Collection<ASAPCertificate> newCerts = this.readReceivedCertificates(this.certificatesBySubjectIDMap);
        if(!newCerts.isEmpty()) {
            // reset identity assurance - is most likely changed
            this.userIdentityAssurance = null;
        }

        return newCerts;
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
        this.certificatesBySubjectIDMap = null;
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
        this.certificatesBySubjectIDMap = null;
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

    protected abstract Collection<ASAPCertificate>
        readReceivedCertificates(Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap);

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

    public boolean verify(ASAPCertificate cert, PublicKey publicKey) {
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

    private IdentityAssurance getIdentityAssurance(CharSequence userID, ASAPCertificateStore asapPKI)
            throws ASAPSecurityException {
        // general setup?
        if(this.userIdentityAssurance == null) {
            this.userIdentityAssurance = new HashMap<CharSequence, IdentityAssurance>();
            this.setupIdentityAssurance(userID, asapPKI);
        }

        IdentityAssurance identityAssurance = this.userIdentityAssurance.get(userID);
        // setup individual user?
        if(identityAssurance == null) {
            // setup
            this.setupIdentityAssurance(userID, asapPKI);
            // try again
            identityAssurance = this.userIdentityAssurance.get(userID);
        }

        return identityAssurance;
    }

    @Override
    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID, ASAPCertificateStore asapPKI)
            throws ASAPSecurityException {

        return this.getIdentityAssurance(userID, asapPKI).path;
    }

    public int getIdentityAssurances(CharSequence userID, ASAPCertificateStore ASAPCertificateStore) throws ASAPSecurityException {
        return this.getIdentityAssurance(userID, ASAPCertificateStore).getValue();
    }

    private void setupIdentityAssurance(CharSequence userID, ASAPCertificateStore ASAPCertificateStore) throws ASAPSecurityException {
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
                        if(certificate.verify(ASAPCertificateStore.getPublicKey())) {
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
                throw new ASAPSecurityException
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
                    userID, certificate, -1, ASAPCertificateStore);

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
            ASAPCertificateStore ASAPCertificateStore)
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
                publicKey = ASAPCertificateStore.getPublicKey();
                if(!this.verify(currentCertificate, publicKey)) {
                    return this.worstIdentityAssurance;
                }
            } catch (ASAPSecurityException e) {
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
            float failureProbability = ((float) ASAPCertificateStore.getSigningFailureRate(proceedingPersonID)) / 10;

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
                    ASAPCertificateStore);

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
            this(ASAPCertificateStorage.CERTIFICATE_APP_NAME, ASAPCertificate.ASAP_CERTIFICATE_URI, era);
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
