package net.sharksystem.crypto;

import net.sharksystem.asap.*;
import net.sharksystem.asap.apps.ASAPMessages;
import net.sharksystem.asap.util.Log;

import javax.management.RuntimeErrorException;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class ASAPCertificateStorageImpl extends CertificateStorageImpl {

    private final ASAPStorage asapStorage;

    public ASAPCertificateStorageImpl(ASAPStorage asapStorage, CharSequence ownerID, CharSequence ownerName) {
        super(ownerID, ownerName);
        this.asapStorage = asapStorage;
    }

    public int getEra() {
        return this.asapStorage.getEra();
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                               ASAP Wrapper                                                //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private ASAPCertificate addCertificate2InMemo(byte[] message, ASAPStorageAddressImpl asapStorageAddress,
                                       Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap,
                                       List<ASAPCertificate> expiredCertificates)
            throws ASAPException, SharkCryptoException {
        String text = "nothing";
        try {
            ASAPCertificate asapCertificate =
                    ASAPCertificateImpl.produceCertificateFromByteArray(message, asapStorageAddress);

            // expired
            if(this.isExpired(asapCertificate)) {
                // set on delete list - if any
                if(expiredCertificates != null) expiredCertificates.add(asapCertificate);
            } else {
                // valid - keep in memory
                CharSequence ownerID = asapCertificate.getSubjectID();
                // add to in-memo structure
                Set<ASAPCertificate> certSet = certificatesByOwnerIDMap.get(ownerID);

                boolean addCert = true;
                if (certSet == null) {
                    certSet = new HashSet<>();
                    certificatesByOwnerIDMap.put(ownerID, certSet);
                } else {
                    // check if certificate already in there
                    for(ASAPCertificate cert : certSet) {
                        if(cert.isIdentical(asapCertificate)) {
                            Log.writeLog(this, "found identical certificate - don't add new one");
                            addCert = false;
                            throw new SharkCryptoException("certificate already exists");
                        }
                    }
                }

                if(addCert) {
                    certSet.add(asapCertificate);
                }

                return asapCertificate;
            }
        } catch (RuntimeErrorException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            text = "cannot create certificate: " + e.getLocalizedMessage();
            Log.writeLog(this, text);
        }

        // with no previous exception - we don't reach that line
        throw new ASAPException(text);
    }

    protected void readCertificatesFromStorage(Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap) {
        int era = this.asapStorage.getOldestEra();
        int thisEra = this.asapStorage.getEra();
        Log.writeLog(this, "readCertificatesFromStorage oldestEra/thisEra: " + era + " | " + thisEra);
        ASAPChunkStorage chunkStorage = this.asapStorage.getChunkStorage();
        boolean lastRound = false;
        List<ASAPCertificate> expiredCertificates = new ArrayList<>();
        do {
            lastRound = era == thisEra;

            try {
                ASAPChunk chunk = chunkStorage.getChunk(ASAPCertificate.ASAP_CERTIFICATE_URI, era);
                Iterator<byte[]> messagesAsBytes = chunk.getMessagesAsBytes();
                // create address
                ASAPStorageAddressImpl asapStorageAddress = new ASAPStorageAddressImpl(era);
                while(messagesAsBytes.hasNext()) {
                    try {
                        this.addCertificate2InMemo(
                                messagesAsBytes.next(), asapStorageAddress,
                                certificatesByOwnerIDMap, expiredCertificates);
                    } catch (SharkCryptoException e) {
                        // certificate already exists - try next
                    }
                }
            } catch (IOException | ASAPException e) {
                Log.writeLog(this, "exception when read certificates from asap storage: "
                        + e.getLocalizedMessage());
            }

            // next era
            era = this.asapStorage.getNextEra(era);
        } while(!lastRound);

       // remove expired certificates from asap memory
        try {
            this.removeCertificatesFromStorage(expiredCertificates);
        } catch (IOException e) {
            Log.writeLog(this, "cannot remove certificate: " + e.getLocalizedMessage());
        }

        // read received certificates
        this.readReceivedCertificates(certificatesByOwnerIDMap);
    }

    protected Collection<ASAPCertificate> readReceivedCertificates(
            Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap) {

//        Log.writeLog(this, "readReceivedCertificates");
        Collection<ASAPCertificate> asapCertificatesReceived = new ArrayList<>();

//        Log.writeLog(this, "look for chunk storage...");
        ASAPChunkStorage chunkStorage = this.asapStorage.getChunkStorage();
//        Log.writeLog(this, "...got it: " + this.asapStorage);

        try {
            List<CharSequence> senderList = this.asapStorage.getSender();
            Log.writeLog(this, "got sender list" + senderList);
            // at least one sender - get access to owner channel to copy messages to
            this.asapStorage.createChannel(ASAPCertificate.ASAP_CERTIFICATE_URI);
            ASAPChannel ownerCertificateChannel = null;
            try {
                 ownerCertificateChannel = this.asapStorage.getChannel(ASAPCertificate.ASAP_CERTIFICATE_URI);
            }
            catch(ASAPException e) {
                // channel does not exist yet - set it up
                this.asapStorage.createChannel(ASAPCertificate.ASAP_CERTIFICATE_URI);
                ownerCertificateChannel = this.asapStorage.getChannel(ASAPCertificate.ASAP_CERTIFICATE_URI);
                // exception can be thrown if creation is impossible - that's ok though
            }
//            Log.writeLog(this, "got ownerCertificateChannel");
            ASAPStorageAddressImpl asapStorageAddress = new ASAPStorageAddressImpl(this.asapStorage.getEra());
//            Log.writeLog(this, "created address");

            for(CharSequence sender : senderList) {
//                Log.writeLog(this, "read certificates received from " + sender);
                ASAPStorage incomingStorage = this.asapStorage.getExistingIncomingStorage(sender);
//                Log.writeLog(this, "got existing asap storage " + sender);
                ASAPChunkStorage incomingChunkStorage = incomingStorage.getChunkStorage();
//                Log.writeLog(this, "got chunk storage " + sender);
                ASAPMessages incomingChunkCache =
                        incomingChunkStorage.getASAPChunkCache(ASAPCertificate.ASAP_CERTIFICATE_URI,
                                ASAP.INITIAL_ERA, ASAP.MAX_ERA);
//                Log.writeLog(this, "got chunk cache from " + sender + " of "
//                      + ASAPCertificate.ASAP_CERTIFICATE_URI);

                Iterator<byte[]> messages = incomingChunkCache.getMessages();
//                Log.writeLog(this, "iterate messages");
                while(messages.hasNext()) {
                    byte[] message = messages.next();
                    // write into owners channel
//                    Log.writeLog(this, "copy message in owners channel");
                    ownerCertificateChannel.addMessage(message);

                    // deserialize
//                    Log.writeLog(this, "add to internal certificate list");

                    // remember new certificates - don't collect expired certs - they will be removed anyway
                    try {
                        asapCertificatesReceived.add(
                            this.addCertificate2InMemo(message, asapStorageAddress,
                                    certificatesByOwnerIDMap, null));
                    } catch (SharkCryptoException e) {
                        // cert already exists - try next
                    }
                }

                // delete
//                Log.writeLog(this, "remove channel in incoming storage");
                incomingStorage.removeChannel(ASAPCertificate.ASAP_CERTIFICATE_URI);
            }
        } catch (IOException | ASAPException e) {
            Log.writeLog(this, "exception when looking for received certificates - give up: "
                    + e.getLocalizedMessage());
        }

        return asapCertificatesReceived;
    }

    @Override
    public ASAPStorageAddress storeCertificateInStorage(ASAPCertificate asapCertificate) throws IOException {
        Log.writeLog(this, "call asapStorage.add() to store certificate");
        this.asapStorage.add(asapCertificate.ASAP_CERTIFICATE_URI, asapCertificate.asBytes());

        Log.writeLog(this, "create asap certificate address object");
        ASAPStorageAddressImpl asapStorageAddress = new ASAPStorageAddressImpl(
                this.asapStorage.getFormat(),
                asapCertificate.ASAP_CERTIFICATE_URI,
                this.asapStorage.getEra());

        // remember location
        if(asapCertificate instanceof ASAPCertificateImpl) {
            ASAPCertificateImpl asapCertImp = (ASAPCertificateImpl) asapCertificate;
            asapCertImp.setASAPStorageAddress(asapStorageAddress);
        }

        return asapStorageAddress;
    }

    protected void removeCertificateFromStorage(ASAPCertificate cert2remove) throws IOException {
        ASAPStorageAddress asapAddress = cert2remove.getASAPStorageAddress();
        if (asapAddress == null) {
            Log.writeLog(this, "asap address must not be null - cannot remove");
            return;
        }

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
                                ASAPCertificateImpl.produceCertificateFromByteArray(messageBytes, asapAddress);

                        // to be dropped?
                        if (asapCertificate.getSubjectID() == cert2remove.getSubjectID()
                                && asapCertificate.getIssuerID() == cert2remove.getIssuerID()) {
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
}
