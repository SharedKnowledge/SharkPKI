package net.sharksystem.certificates;

import net.sharksystem.asap.ASAPChunk;
import net.sharksystem.asap.ASAPChunkStorage;
import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.asap.util.Log;

import java.io.*;
import java.util.*;

public class ASAPCertificateStorageImpl implements ASAPCertificateStorage {
    public static final String ASAP_CERIFICATE_APP = "asapCertificates";

    private final ASAPStorage asapStorage;
    private final int ownerID;

    public ASAPCertificateStorageImpl(ASAPStorage asapStorage, int ownerID) {
        this.asapStorage = asapStorage;
        this.ownerID = ownerID;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            identity assurance                                            //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public int getIdentityAssurances(int userID, PersonCertificateExchangeFailureStorage pcefs) {
        Collection<ASAPCertificate> certificates = this.getCertificatesByOwnerID(userID);
        if (certificates == null || certificates.isEmpty()) {
            // we don't know anything about this person
            return LOWEST_IDENTITY_ASSURANCE_LEVEL;
        }
        else {
        // we have got one or more certificates - find best one
            // first: is there one certificate issued by owner?
            for(ASAPCertificate certificate : certificates) {
                if (certificate.getSignerID() == userID) {
                    return HIGHEST_IDENTITY_ASSURANCE_LEVEL;
                }
            }
        }

        // we have certificates but nothing issued by owner - let's look for the best one
        int bestAssurance = LOWEST_IDENTITY_ASSURANCE_LEVEL;
        // the certificates chain - for each certificate
        for(ASAPCertificate certificate : certificates) {
            Set<Integer> idChain = new HashSet<>(); // init chain
            idChain.add(userID); // we have already found a certificate for this person

            int identityAssurance = this.calculateIdentityAssurance(
                    idChain, certificate.getSignerID(), -1, pcefs);

            // impossible in version 1 - but maybe in another algorithm version
            if(identityAssurance == HIGHEST_IDENTITY_ASSURANCE_LEVEL) return HIGHEST_IDENTITY_ASSURANCE_LEVEL;

            bestAssurance = identityAssurance > bestAssurance ? identityAssurance : bestAssurance;
        }

        return bestAssurance;
    }

    /**
     * Follow chain backward. If it reaches owner.. there will be an assurance level better than
     * worst. If it does not end at owner or even goes in circles - it worst level.
     *
     * @param idChain                     already visited ids
     * @param currentPersonID             current id
     * @param currentAssuranceProbability current assurance so far
     * @return what we lool for:
     * YOU - Person A - Person B - ...- current Person - ... - Person in question
     * <p>
     * We go backward in chain to - hopefully reach you
     */
    private int calculateIdentityAssurance(Set<Integer> idChain, int currentPersonID,
                               float currentAssuranceProbability, PersonCertificateExchangeFailureStorage pcefs) {

        // finished?
        if (currentPersonID == this.ownerID) {
            if(currentAssuranceProbability < LOWEST_IDENTITY_ASSURANCE_LEVEL) {
                // not yet set
                return LOWEST_IDENTITY_ASSURANCE_LEVEL;
            } else {
                return (int) (currentAssuranceProbability * 10); // yes - rescale to 0..10
            }
        }

        // not finished

        // are we in a circle?
        if (idChain.contains(currentPersonID))
            return LOWEST_IDENTITY_ASSURANCE_LEVEL; // yes - escape

        // remember this step
        idChain.add(currentPersonID);

        // calculate failure rate in percent
        float failureProbability = pcefs.getCertificateExchangeFailure(currentPersonID) / 10;

        // OK. We have information about this person. Calculate assuranceLevel
        if (currentAssuranceProbability < LOWEST_IDENTITY_ASSURANCE_LEVEL) {
            // haven't yet calculated any assurance prob. Set initial value
            currentAssuranceProbability = 1 - failureProbability;
        } else {
            currentAssuranceProbability *= 1 - failureProbability;
        }

        // is there a next step? Yes, if there is a certificate
        Collection<ASAPCertificate> nextCertificates = this.getCertificatesByOwnerID(currentPersonID);

        if(nextCertificates == null || nextCertificates.isEmpty()) return LOWEST_IDENTITY_ASSURANCE_LEVEL;

        int bestIdentityAssurance = LOWEST_IDENTITY_ASSURANCE_LEVEL;
        for(ASAPCertificate nextCertificate : nextCertificates) {
            // make a idChain copy
            Set<Integer> nextIDChain = new HashSet<>();
            nextIDChain.addAll(idChain);

            int identityAssurance = this.calculateIdentityAssurance(nextIDChain,
                    nextCertificate.getSignerID(), currentAssuranceProbability, pcefs);

            if(identityAssurance == HIGHEST_IDENTITY_ASSURANCE_LEVEL) return HIGHEST_IDENTITY_ASSURANCE_LEVEL;

            bestIdentityAssurance =
                    identityAssurance > bestIdentityAssurance ? identityAssurance : bestIdentityAssurance;
        }

        return bestIdentityAssurance;
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
                ASAPChunk chunk = chunkStorage.getChunk(ASAPCertificate.ASAP_CERIFICATE_URI, era);
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

            Log.writeLog(this, "we do not read from incoming / sender storages - it's a feature");

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
    public ASAPStorageAddress storeCertificate(ASAPCertificate ASAPCertificate) throws IOException {
        this.asapStorage.add(ASAPCertificate.ASAP_CERIFICATE_URI, ASAPCertificate.asBytes());

        return new ASAPStorageAddressImpl(
                this.asapStorage.getFormat(),
                ASAPCertificate.ASAP_CERIFICATE_URI,
                this.asapStorage.getEra());
    }

    @Override
    public void removeCertificate(ASAPCertificate cert2remove, ASAPStorageAddress asapAddress) throws IOException {
        if(asapAddress == null) {
            Log.writeLog(this, "asap address must not be null");
        }

        // drop in memo copies
        this.certificatesByOwnerIDMap = new HashMap<>();

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
            this(ASAP_CERIFICATE_APP, ASAPCertificate.ASAP_CERIFICATE_URI, era);
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
