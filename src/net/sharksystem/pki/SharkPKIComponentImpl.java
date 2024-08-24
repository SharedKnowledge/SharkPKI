package net.sharksystem.pki;

import net.sharksystem.*;
import net.sharksystem.asap.*;
import net.sharksystem.asap.crypto.*;
import net.sharksystem.asap.persons.*;
import net.sharksystem.asap.pki.ASAPStorageBasedCertificateStore;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.CredentialMessageInMemo;
import net.sharksystem.fs.ExtraData;
import net.sharksystem.testhelper.ASAPTesthelper;
import net.sharksystem.utils.Log;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.util.*;

/**
 * Shark component facade of this certificate / PKI component
 /**
 * This component has three major function:
 * <ul>
 *     <li>It implements <a href="http://sharksystem.net/asap/javadoc/net/sharksystem/asap/crypto/ASAPKeyStore.html">ASAPKeyStore</a></li>
 *     <li>It stores received certificates and offers search methods</li>
 *     <li>It offers means to send a a public key and receive public keys to initiate certificate creation</li>
 * </ul>
 *
 *
 */
class SharkPKIComponentImpl extends AbstractSharkComponent
        implements SharkComponent, ASAPKeyStore, SharkPKIComponent,
        ASAPMessageReceivedListener, ASAPEnvironmentChangesListener {

    private final SharkPeer owner;
    private CharSequence ownerName;
    private SharkCredentialReceivedListener credentialReceivedListener = null;

    public boolean BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER_DEFAULT = false;
    private boolean behaviourSendCredentialFirstEncounter = BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER_DEFAULT;
    private boolean certificateExpected = false;

    public void setBehaviour(String behaviourName, boolean on)
            throws SharkUnknownBehaviourException, ASAPException, IOException {
        this.checkStatus();
        switch(behaviourName) {
            case BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER: {
                // changed?
                if(this.behaviourSendCredentialFirstEncounter == on) {
                    Log.writeLog(this, "behaviour was already set that way - ignore: " + behaviourName);
                    return;
                }
                this.behaviourSendCredentialFirstEncounter = on;
                if(on) {
                    // changed from off -> on
                    this.sendCredentialMessage();
                } else {
                    // changed from on -> off
                    this.removeCredentialMessage();
                }
                break;
            }
            default: super.setBehaviour(behaviourName, on);
        }
    }

    @Override
    public ASAPKeyStore getASAPKeyStore() {
        return this.asapPKIStorage;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                      credential message received                                        //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void setSharkCredentialReceivedListener(SharkCredentialReceivedListener listener) {
        this.checkStatus();
        this.credentialReceivedListener = listener;

        // add listener - even if null - it is handled as reset
        this.asapPeer.addASAPMessageReceivedListener(
                ASAPCertificateAndPersonStore.CREDENTIAL_APP_NAME, this);
    }

    @Override
    public void asapMessagesReceived(ASAPMessages asapMessages,
                                     String senderE2E, // E2E part
                                     List<ASAPHop> asapHops) throws IOException {

        switch (asapMessages.getFormat().toString()) {
            case SharkPKIComponent.PKI_APP_NAME:
                //Log.writeLog(this, "certificate received - done / TODO");
                this.certificateReceived(asapMessages);
                return;
            case SharkPKIComponent.CREDENTIAL_APP_NAME:
                //Log.writeLog(this, "credential received - handle");
                this.credentialReceived(asapMessages);
                break;
        }
    }

    private void certificateReceived(ASAPMessages asapMessages) throws IOException {
        Log.writeLog(this, "certificate received - sync in memo certificate storage with asap storage");
        this.asapCertificateStorage.dropInMemoCache();
        // TODO - sync identity assurance
    }

    private void credentialReceived(ASAPMessages asapMessages) throws IOException {
        if(this.credentialReceivedListener == null) {
            Log.writeLog(this, "received message but no listener - give up");
            return;
        }

        CharSequence uri = asapMessages.getURI();
        if(uri == null || !uri.toString().equalsIgnoreCase(SharkPKIComponent.CREDENTIAL_URI.toString())) {
            Log.writeLog(this, "received message, expect credential message, got instead: " + uri);
            return;
        }

        Iterator<byte[]> messages = asapMessages.getMessages();
        while (messages.hasNext()) {
            try {
                CredentialMessageInMemo credentialMessage = new CredentialMessageInMemo(messages.next());
                this.credentialReceivedListener.credentialReceived(credentialMessage);
            } catch (ASAPException e) {
                Log.writeLog(this, "could not create credential message from asap message " +
                        "- seems to be a bug - check serialization of credential messaging");
            }

        }
    }

    @Override
    public void onlinePeersChanged(Set<CharSequence> onlinePeerList) {
        Log.writeLog(this, this.asapPeer.getPeerID().toString(),
                "notified about changes in peer list: " + onlinePeerList);

        if(onlinePeerList == null || onlinePeerList.isEmpty()) return;

        // is there a peer that has not yet signed our public key?
        for (CharSequence peerID : onlinePeerList) {
            boolean found = false;
            try {
                ASAPCertificate cert = this.getCertificateByIssuerAndSubject(peerID, this.getOwnerID());
                if (cert != null) found = true;
            } catch (ASAPSecurityException e) {
                // no certificate
            }

            if(found) Log.writeLog(this, this.asapPeer.getPeerID().toString(),
                    "found a certificate issued by == " + peerID);

            if (!found && this.behaviourSendCredentialFirstEncounter) {
                Log.writeLog(this, this.asapPeer.getPeerID().toString(),
            "encountered peer that has not yet issued a certificate. Send credential message to: " + peerID);
                try {
                    Log.writeLog(this, "create credential message");
                    CredentialMessage credentialMessage = this.asapPKIStorage.createCredentialMessage();
                    Log.writeLog(this, "credential message == " + credentialMessage);
                    this.asapPeer.sendTransientASAPMessage(ASAPCertificateAndPersonStore.CREDENTIAL_APP_NAME,
                            SharkPKIComponent.CREDENTIAL_URI,
                            credentialMessage.getMessageAsBytes());
                    Log.writeLog(this, "credential message sent");

                    this.certificateExpected = true;

                    break; // already send to anybody
                } catch (IOException | ASAPException e) {
                    Log.writeLogErr(this, e.getLocalizedMessage());
                }
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             startup                                                     //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static final String SHARK_PKI_DATA_KEY = "sharkPKIData";
    private ASAPPKIStorage asapPKIStorage = null;
    private ASAPStorageBasedCertificateStore asapCertificateStorage;
    private ASAPPeer asapPeer = null;
    private InMemoASAPKeyStore asapKeyStore;

    /**
     * For debugging - get access to sub-component
     * @return
     */
    ASAPPKIStorage getASAPPKIStorage() {
        return this.asapPKIStorage;
    }

    SharkPKIComponentImpl(SharkPeer owner) throws SharkException, IOException {
        if(owner == null) throw new SharkException("shark peer must not be null");
        this.owner = owner;
        this.ownerName = owner.getSharkPeerName();
    }

    @Override
    public void onStart(ASAPPeer asapPeer) throws SharkException {
        this.asapPeer = asapPeer;

        try {
            ////// set up pki complete with its subcomponents

            // key management
            this.asapKeyStore = new InMemoASAPKeyStore(asapPeer.getPeerID());
            this.asapKeyStore.setMementoTarget(this.owner.getSharkPeerExtraData());

            // hold messages - serialized certificates
            ASAPStorage asapStorage = asapPeer.getASAPStorage(ASAPCertificateStorage.PKI_APP_NAME);
            CharSequence peerName = this.ownerName != null ? this.ownerName : asapPeer.getPeerID();

            // this object can interpret those messages as certificates; it requires no further persistence
            this.asapCertificateStorage =
                new ASAPStorageBasedCertificateStore(asapStorage, asapPeer.getPeerID(), peerName);

            // bind components together and add person values support
            this.asapPKIStorage = new ASAPPKIStorage(this.asapCertificateStorage, this.asapKeyStore);

            // Save memento with shark peer (not asap peer)
            this.asapPKIStorage.setMementoTarget(this.owner.getSharkPeerExtraData());

            try {
                try {
                    byte[] memento = this.asapPeer.getExtra(SHARK_PKI_DATA_KEY);
                    this.asapPKIStorage.restoreMemento(memento);
                }
                catch(SharkException se) {
                    Log.writeLog(this, "no memento present - component was not used before");
                }

            } catch (IOException e) {
                throw new SharkException(e);
            }

            // get notified about new peer in the neighbourhood
            this.asapPeer.addASAPEnvironmentChangesListener(this);

            this.asapPeer.addASAPMessageReceivedListener(SharkPKIComponent.PKI_APP_NAME, this);

        } catch (IOException | ASAPException e) {
            throw new SharkException(e);
        }
    }

    private void checkStatus() throws SharkStatusException {
        if(this.asapPKIStorage == null) {
            throw new SharkStatusException("ASAP peer not started component not yet initialized");
        }

        if(this.certificateExpected) {
            this.certificateExpected = false;
            // good chance that something was received
            this.asapCertificateStorage.dropInMemoCache();
            this.asapPKIStorage.incorporateReceivedCertificates();
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                               delegate                                                  //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public PublicKey getPublicKey(CharSequence charSequence) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPublicKey(charSequence);
    }

    @Override
    public boolean isOwner(CharSequence charSequence) {
        this.checkStatus();
        return this.asapPKIStorage.isOwner(charSequence);
    }

    @Override
    public CharSequence getOwner() {
        this.checkStatus();
        return this.asapPKIStorage.getOwner();
    }

    /**
     * Remove credential messages from outbox. It used
     * a) behaviour is changed to not issuing a credential during encounter or
     * b) new keypair was created.
     */
    private void removeCredentialMessage() throws IOException, ASAPException {
        Log.writeLog(this, "remove credential channel");
        ASAPStorage credentialStorage = this.asapPeer.getASAPStorage(SharkPKIComponent.CREDENTIAL_APP_NAME);
        credentialStorage.removeChannel(SharkPKIComponent.CREDENTIAL_URI);
    }

    /**
     * Add credential messages to outbox. It used
     * a) behaviour is changed to not issuing a credential during encounter or
     * b) new keypair was created.
     */
    private void sendCredentialMessage() throws ASAPException, IOException {
        Log.writeLog(this, "create credential message");
        CredentialMessage credentialMessage = this.asapPKIStorage.createCredentialMessage();
        Log.writeLog(this, "credential message == " + credentialMessage);
        this.asapPeer.sendASAPMessage(
                SharkPKIComponent.CREDENTIAL_APP_NAME,
                SharkPKIComponent.CREDENTIAL_URI,
                credentialMessage.getMessageAsBytes());
        Log.writeLog(this, "credential message sent");
    }

    @Override
    public void createNewKeyPair() throws ASAPException, IOException {
        this.checkStatus();
        this.asapPKIStorage.generateKeyPair();

        if(this.behaviourSendCredentialFirstEncounter) {
            this.removeCredentialMessage();
            this.sendCredentialMessage();
        }
    }

    @Override
    public void generateKeyPair() throws ASAPSecurityException {
        try {
            this.createNewKeyPair();
        } catch (ASAPException | IOException asapException) {
            throw new ASAPSecurityException("problems when creating key pair", asapException);
        }
    }

    @Override
    public CharSequence getOwnerID() {
        this.checkStatus();
        return this.asapPKIStorage.getOwnerID();
    }

    @Override
    public CharSequence getOwnerName() {
        this.checkStatus();
        return this.asapPKIStorage.getOwnerName();
    }

    @Override
    public PrivateKey getPrivateKey() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPrivateKey();
    }

    @Override
    public PublicKey getPublicKey() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPublicKey();
    }

    @Override
    public long getKeysCreationTime() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getKeysCreationTime();
    }

    @Override
    public ASAPCertificate acceptAndSignCredential(CredentialMessage credentialMessage)
            throws IOException, ASAPSecurityException {

        this.checkStatus();
        ASAPCertificate asapCertificate = this.asapPKIStorage.addAndSignPerson(credentialMessage.getSubjectID(),
                credentialMessage.getSubjectName(),
                credentialMessage.getPublicKey(),
                credentialMessage.getValidSince());

        this.asapCertificateStorage.dropInMemoCache();

        // spread the news - we have got a new certificate
        try {
            this.asapPeer.sendASAPMessage(ASAPCertificateStorage.PKI_APP_NAME,
                    ASAPCertificate.ASAP_CERTIFICATE_URI, asapCertificate.asBytes());

        } catch (ASAPException e) {
            Log.writeLog(this, "could not send certificate to online peers (ignored): " + e.getLocalizedMessage());
        }

        return asapCertificate;
    }

    /*
    public ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince) throws ASAPSecurityException, IOException {
        this.checkStatus();
        return this.asapPKIStorage.addAndSignPerson(userID, userName, publicKey, validSince);
    }
     */

    @Override
    public void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException {
        this.checkStatus();
        this.asapPKIStorage.setSigningFailureRate(personID, failureRate);
    }

    @Override
    public int getSigningFailureRate(CharSequence personID) {
        this.checkStatus();
        return this.asapPKIStorage.getSigningFailureRate(personID);
    }

    @Override
    public PersonValues getPersonValuesByPosition(int position) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPersonValuesByPosition(position);
    }

    @Override
    public PersonValues getPersonValuesByID(CharSequence peerID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPersonValues(peerID);
    }

    public Set<PersonValues> getPersonValuesByName(CharSequence peerName) throws ASAPException {
        this.checkStatus();
        if(this.getNumberOfPersons() < 1) throw new ASAPException("no peers at all");
        Set<PersonValues> personValuesSet = new HashSet<>();
        for(int i = 0; i < this.getNumberOfPersons(); i++) {
            PersonValues personValuesByPosition = this.getPersonValuesByPosition(i);
            if(peerName.toString().equalsIgnoreCase(personValuesByPosition.toString())) {
                personValuesSet.add(personValuesByPosition);
            }
        }
        if(personValuesSet.isEmpty()) throw new ASAPException("there is not peer with name " + peerName);
        return personValuesSet;
    }

    @Override
    public int getNumberOfPersons() {
        this.checkStatus();
        return this.asapPKIStorage.getNumberOfPersons();
    }

    @Override
    public int getIdentityAssurance(CharSequence userID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getIdentityAssurance(userID);
    }

    @Override
    public List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getIdentityAssurancesCertificationPath(userID);
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getCertificatesBySubject(subjectID);
    }

    public Set<ASAPCertificate> getCertificates() {
        this.checkStatus();
        return this.asapPKIStorage.getAllCertificates();
    }

    @Override
    public Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getCertificatesByIssuer(issuerID);
    }

    @Override
    public ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getCertificateByIssuerAndSubject(issuerID, subjectID);
    }

    @Override
    public void addCertificate(ASAPCertificate asapCertificate) throws IOException, ASAPException {
        this.checkStatus();
        this.asapPKIStorage.addCertificate(asapCertificate);
        this.saveMemento();
    }

    @Override
    public boolean verifyCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        this.checkStatus();
        return this.asapPKIStorage.verifyCertificate(asapCertificate);
    }

    /*
    @Override
    public CredentialMessage createCredentialMessage() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.createCredentialMessage();
    }

    @Override
    public CredentialMessage createCredentialMessage(byte[] extraData) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.createCredentialMessage(extraData);
    }
     */

    @Override
    public void sendTransientCredentialMessage(CredentialMessage credentialMessage) throws ASAPException, IOException {
        this.checkStatus();
        this.asapPeer.sendTransientASAPMessage(
                SharkPKIComponent.CREDENTIAL_APP_NAME,
                SharkPKIComponent.CREDENTIAL_URI,
                credentialMessage.getMessageAsBytes());
    }

    @Override
    public void sendTransientCredentialMessage() throws ASAPException, IOException {
        this.checkStatus();
        CredentialMessage credentialMessage = this.asapPKIStorage.createCredentialMessage();
        this.asapPeer.sendTransientASAPMessage(
                SharkPKIComponent.CREDENTIAL_APP_NAME,
                SharkPKIComponent.CREDENTIAL_URI,
                credentialMessage.getMessageAsBytes());
    }

    public void sendTransientCredentialMessage(CharSequence peerID) throws ASAPException, IOException {
        this.checkStatus();
        CredentialMessage credentialMessage = this.asapPKIStorage.createCredentialMessage();
        this.asapPeer.sendTransientASAPMessage(
                peerID,
                SharkPKIComponent.CREDENTIAL_APP_NAME,
                SharkPKIComponent.CREDENTIAL_URI,
                credentialMessage.getMessageAsBytes());
    }

    @Override
    public boolean syncNewReceivedCertificates() throws IOException, ASAPException {
        this.checkStatus();
        boolean retVal = this.asapPKIStorage.incorporateReceivedCertificates();
        this.saveMemento();
        return retVal;
    }

    public void saveMemento() {
        this.asapPKIStorage.save();
    }

    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        this.checkStatus();
        return this.asapPKIStorage.getAsymmetricEncryptionAlgorithm();
    }

    @Override
    public String getAsymmetricSigningAlgorithm() {
        this.checkStatus();
        return this.asapPKIStorage.getAsymmetricSigningAlgorithm();
    }

    @Override
    public SecretKey generateSymmetricKey() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.generateSymmetricKey();
    }

    @Override
    public String getSymmetricEncryptionAlgorithm() {
        this.checkStatus();
        return this.asapPKIStorage.getSymmetricEncryptionAlgorithm();
    }

    @Override
    public String getSymmetricKeyType() {
        this.checkStatus();
        return this.asapPKIStorage.getSymmetricKeyType();
    }

    @Override
    public int getSymmetricKeyLen() {
        this.checkStatus();
        return this.asapPKIStorage.getSymmetricKeyLen();
    }
}
