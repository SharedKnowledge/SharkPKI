package net.sharksystem.crypto;

import net.sharksystem.asap.ASAPChunk;
import net.sharksystem.asap.ASAPChunkStorage;
import net.sharksystem.asap.ASAPStorage;
import net.sharksystem.asap.util.Log;

import java.io.*;
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

    protected void readCertificatesFromStorage(Map<CharSequence, Set<ASAPCertificate>> certificatesByOwnerIDMap) {
        int era = this.asapStorage.getOldestEra();
        int thisEra = this.asapStorage.getEra();
        ASAPChunkStorage chunkStorage = this.asapStorage.getChunkStorage();
        boolean lastRound = false;
        List<ASAPCertificate> expiredCertificates = new ArrayList<>();
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

                        // expired
                        if(this.isExpired(asapCertificate)) {
                            // remove
                            expiredCertificates.add(asapCertificate);
                        } else {
                            // valid - keep in memory
                            CharSequence ownerID = asapCertificate.getSubjectID();
                            // add to in-memo structure
                            Set<ASAPCertificate> certSet =
                                    certificatesByOwnerIDMap.get(ownerID);

                            if (certSet == null) {
                                certSet = new HashSet<>();
                                certificatesByOwnerIDMap.put(ownerID, certSet);
                            }
                            certSet.add(asapCertificate);
                        }
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

        // remove expired certificates from asap memory
        for(ASAPCertificate cert2remove : expiredCertificates) {
            try {
                this.removeCertificateFromStorage(cert2remove);
            } catch (IOException e) {
                Log.writeLog(this, "cannot remove certificate: " + e.getLocalizedMessage());
            }
        }
    }

    @Override
    public ASAPStorageAddress storeCertificateInStorage(ASAPCertificate asapCertificate) throws IOException {
        this.asapStorage.add(asapCertificate.ASAP_CERTIFICATE, asapCertificate.asBytes());

        ASAPStorageAddressImpl asapStorageAddress = new ASAPStorageAddressImpl(
                this.asapStorage.getFormat(),
                asapCertificate.ASAP_CERTIFICATE,
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
                                ASAPCertificateImpl.produceCertificateFromStorage(messageBytes, asapAddress);

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
