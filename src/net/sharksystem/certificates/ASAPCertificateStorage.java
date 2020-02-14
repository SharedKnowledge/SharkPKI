package net.sharksystem.certificates;

import net.sharksystem.asap.ASAPStorage;

import java.io.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class ASAPCertificateStorage implements CertificateStorage {
    private final ASAPStorage asapStorage;
    private final int ownerID;

    public ASAPCertificateStorage(ASAPStorage asapStorage, int ownerID) {
        this.asapStorage = asapStorage;
        this.ownerID = ownerID;
    }

    public int getIdentityAssurances(int userID, PersonCertificateExchangeFailureStorage pcefs) {
        Collection<SharkCertificate> certificates = this.getCertificatesByOwnerID(userID);
        if (certificates == null || certificates.isEmpty()) {
            // we don't know anything about this person
            return LOWEST_IDENTITY_ASSURANCE_LEVEL;
        }
        else {
        // we have got one or more certificates - find best one
            // first: is there one certificate issued by owner?
            for(SharkCertificate certificate : certificates) {
                if (certificate.getSignerID() == userID) {
                    return HIGHEST_IDENTITY_ASSURANCE_LEVEL;
                }
            }
        }

        // we have certificates but nothing issued by owner - let's look for the best one
        int bestAssurance = LOWEST_IDENTITY_ASSURANCE_LEVEL;
        // the certificates chain - for each certificate
        for(SharkCertificate certificate : certificates) {
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
        Collection<SharkCertificate> nextCertificates = this.getCertificatesByOwnerID(currentPersonID);

        if(nextCertificates == null || nextCertificates.isEmpty()) return LOWEST_IDENTITY_ASSURANCE_LEVEL;

        int bestIdentityAssurance = LOWEST_IDENTITY_ASSURANCE_LEVEL;
        for(SharkCertificate nextCertificate : nextCertificates) {
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

    @Override
    public Collection<SharkCertificate> getCertificatesByOwnerID(int userID) {
        // TODO
        return null;
    }

    @Override
    public ASAPStorageAddress storeCertificate(SharkCertificate sharkCertificate) throws IOException {
        this.asapStorage.add(SharkCertificate.ASAP_CERIFICATE_URI, sharkCertificate.asBytes());

        return new ASAPStorageAddressImpl(
                this.asapStorage.getFormat(),
                SharkCertificate.ASAP_CERIFICATE_URI,
                this.asapStorage.getEra());
    }

    @Override
    public void removeCertificate(SharkCertificate sharkCertificate, ASAPStorageAddress asapAddress) {
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