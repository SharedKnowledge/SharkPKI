package net.sharksystem.crypto;

import net.sharksystem.SharkException;
import net.sharksystem.asap.ASAPChunk;
import net.sharksystem.asap.ASAPChunkStorage;
import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.asap.util.Log;
import net.sharksystem.persons.OtherPerson;

import java.io.*;
import java.util.*;

public class ASAPCertificateStorageImpl implements ASAPCertificateStorage {

    private final ASAPStorage asapStorage;
    private final int ownerID;
    private final CharSequence ownerName;

    public ASAPCertificateStorageImpl(ASAPStorage asapStorage, int ownerID, CharSequence ownerName) {
        this.asapStorage = asapStorage;
        this.ownerID = ownerID;
        this.ownerName = ownerName;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            identity assurance                                            //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public int getIdentityAssurances(int userID, PersonCertificateExchangeFailureStorage pcefs)
            throws SharkException {

        Collection<ASAPCertificate> certificates = this.getCertificatesByOwnerID(userID);
        if (certificates == null || certificates.isEmpty()) {
            // we don't know anything about this person
            return OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL;
        }
        else {
        // do we have a certificate signed by owner?
            for(ASAPCertificate certificate : certificates) {
                if (certificate.getSignerID() == this.ownerID) {
                    return OtherPerson.HIGHEST_IDENTITY_ASSURANCE_LEVEL;
                }
            }
        }

        // we have certificates but nothing issued by owner - we look for a certificated way from owner to userID
        Set<Integer> idChain = new HashSet<>(); // init chain

        // find a path and calculate best failure rate of it
        float identityProbability = this.calculateIdentityProbability(idChain,
                userID, -1, pcefs);

        if(identityProbability < 0)
            return OtherPerson.LOWEST_IDENTITY_ASSURANCE_LEVEL;

        // scale, cut and return
        return (int) (identityProbability * 10);
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
    private float calculateIdentityProbability(Set<Integer> idPath, int currentPersonID,
                                               float accumulatedIdentityProbability,
                                               PersonCertificateExchangeFailureStorage pcefs)
            throws SharkException {

        // finished?
        if (currentPersonID == this.ownerID) {
            if(accumulatedIdentityProbability < 0) {
                // not yet set
                return 0; // no
            } else {
                return accumulatedIdentityProbability; // done
            }
        }

        // not finished

        // are we in a circle?
        if (idPath.contains(currentPersonID)) return 0; // escape circle

        // are we already on the path - if not: no need to calculate anything
        if(!idPath.isEmpty()) {
            // convert failure rate number to failure probability something between 0 and 1.
            float failureProbability = ((float) pcefs.getCertificateExchangeFailure(currentPersonID)) / 10;

            // OK. We have information about this person. Calculate assuranceLevel
                /*
                Only the owner is expected to make no failure during certificate exchange. (That's an illusion but
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
        }

        // remember this step
        idPath.add(currentPersonID);

        // is there a next step towards owner? Yes, if there is a certificate owner by the current signer
        Collection<ASAPCertificate> nextCertificates = this.getCertificatesByOwnerID(currentPersonID);

        if(nextCertificates == null || nextCertificates.isEmpty())
            // no certificate - worst failure rate.
            return 0;

        // next step in depth-first search
        float bestIdentityProbability = 0;
        for(ASAPCertificate nextCertificate : nextCertificates) {
            // make a idPath copy
            Set<Integer> copyIDPath = new HashSet<>();
            copyIDPath.addAll(idPath);

            float identityProbability = this.calculateIdentityProbability(copyIDPath,
                    nextCertificate.getSignerID(), accumulatedIdentityProbability, pcefs);

            bestIdentityProbability =
                    identityProbability > bestIdentityProbability ? identityProbability : bestIdentityProbability;
        }

        return bestIdentityProbability;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                               ASAP Wrapper                                                //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private Map<Integer, Set<ASAPCertificate>> certificatesByOwnerIDMap = null;

    private void readCertificatesFromStorage() {
        int era = this.asapStorage.getOldestEra();
        int thisEra = this.asapStorage.getEra();
        ASAPChunkStorage chunkStorage = this.asapStorage.getChunkStorage();
        boolean lastRound = false;
        do {
            lastRound = era == thisEra;

            try {
                ASAPChunk chunk = chunkStorage.getChunk(ASAPCertificate.ASAP_CERTIFICATE, era);
                Iterator<byte[]> messagesAsBytes = chunk.getMessagesAsBytes();
                // create address
                ASAPStorageAddressImpl asapStorageAddress = new ASAPStorageAddressImpl(era);
                while(messagesAsBytes.hasNext()) {
                    try {
                        ASAPCertificateImpl asapCertificate =
                                ASAPCertificateImpl.produceCertificateFromStorage(
                                        messagesAsBytes.next(), asapStorageAddress);

                        int ownerID = asapCertificate.getOwnerID();
                        // add to in-memo structure
                        Set<ASAPCertificate> certSet =
                                this.certificatesByOwnerIDMap.get(ownerID);

                        if(certSet == null) {
                            certSet = new HashSet<>();
                            this.certificatesByOwnerIDMap.put(ownerID, certSet);
                        }
                        certSet.add(asapCertificate);

                    } catch (Exception e) {
                        Log.writeLog(this, "cannot create certificate: " + e.getLocalizedMessage());
                    }
                }
            } catch (IOException e) {
                Log.writeLog(this, "exception when read certificates from asap storage: "
                        + e.getLocalizedMessage());
            }

            // next era
            era = this.asapStorage.getNextEra(era);

            Log.writeLog(this, "info: we do not read from incoming / sender storages - it's a feature");

        } while(!lastRound);
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesByOwnerID(int userID) {
        if(this.certificatesByOwnerIDMap == null) {
            this.certificatesByOwnerIDMap = new HashMap<>();
            this.readCertificatesFromStorage();
        }

        return this.certificatesByOwnerIDMap.get(userID);
    }

    @Override
    public ASAPStorage getASAPStorage() {
        return this.asapStorage;
    }

    @Override
    public int getOwnerID() {
        return this.ownerID;
    }

    @Override
    public CharSequence getOwnerName() {
        return this.ownerName;
    }

    @Override
    public ASAPStorageAddress storeCertificate(ASAPCertificate ASAPCertificate) throws IOException {
        this.asapStorage.add(ASAPCertificate.ASAP_CERTIFICATE, ASAPCertificate.asBytes());

        // drop cache
        this.certificatesByOwnerIDMap = null;

        return new ASAPStorageAddressImpl(
                this.asapStorage.getFormat(),
                ASAPCertificate.ASAP_CERTIFICATE,
                this.asapStorage.getEra());
    }

    @Override
    public void removeCertificate(ASAPCertificate cert2remove, ASAPStorageAddress asapAddress) throws IOException {
        if(asapAddress == null) {
            Log.writeLog(this, "asap address must not be null");
        }

        // drop in memo copies
        this.certificatesByOwnerIDMap = null;

        if(this.asapStorage.getChunkStorage().existsChunk(asapAddress.getUri(), asapAddress.getEra())) {
            ASAPChunkStorage chunkStorage = this.asapStorage.getChunkStorage();

            ASAPChunk chunk = chunkStorage.getChunk(asapAddress.getUri(), asapAddress.getEra());
            if(chunk.getNumberMessage() == 1) {
                // just on certificate in there - it must be the one - remove whole chunk and we are done here
                chunk.drop(); //
                return;
            }

            Iterator<byte[]> messagesAsBytes = chunk.getMessagesAsBytes();
            List<byte[]> tempCopy = new ArrayList<>();
            boolean found = false;

            while(messagesAsBytes.hasNext()) {
                byte[] messageBytes = messagesAsBytes.next();
                try {
                    if(!found) {
                        ASAPCertificateImpl asapCertificate =
                                ASAPCertificateImpl.produceCertificateFromStorage(messageBytes, asapAddress);

                        // to be dropped?
                        if (asapCertificate.getOwnerID() == cert2remove.getOwnerID()
                                && asapCertificate.getSignerID() == cert2remove.getSignerID()) {
                            found= true;
                            continue;
                        }
                    }

                    // keep a temporary copy
                    tempCopy.add(messageBytes);
                } catch (Exception e) {
                    Log.writeLogErr(this, "serious problem: wrong format in my own certificate storage: "
                            + e.getLocalizedMessage());
                }
            }

            if(!found) {
                Log.writeLog(this, "could not remove certificate: not found");
                return;
            }

            // drop and write remaining certs
            chunk.drop();
            chunk = chunkStorage.getChunk(asapAddress.getUri(), asapAddress.getEra());

            for(byte[] message : tempCopy) {
                chunk.addMessage(message);
            }
        }
    }

    public ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException {
        return new ASAPStorageAddressImpl(serializedAddress);
    }

    private class ASAPStorageAddressImpl implements ASAPStorageAddress {
        private final int era;
        private final CharSequence uri;
        private final CharSequence format;

        ASAPStorageAddressImpl(CharSequence format, CharSequence uri, int era) {
            this.format = format;
            this.uri = uri;
            this.era = era;
        }

        ASAPStorageAddressImpl(int era) {
            this(ASAP_CERIFICATE_APP, ASAPCertificate.ASAP_CERTIFICATE, era);
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
