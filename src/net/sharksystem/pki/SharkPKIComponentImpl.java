package net.sharksystem.pki;

import net.sharksystem.*;
import net.sharksystem.asap.*;
import net.sharksystem.asap.crypto.*;
import net.sharksystem.asap.persons.*;
import net.sharksystem.asap.pki.ASAPAbstractCertificateStore;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.pki.CredentialMessageInMemo;
import net.sharksystem.utils.Log;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

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

    private SharkCredentialReceivedListener credentialReceivedListener = null;

    private boolean behaviourSendCredentialFirstEncounter = false;
    private boolean certificateExpected = false;

    public void setBehaviour(String behaviourName, boolean on) throws SharkUnknownBehaviourException, IOException, ASAPException {
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

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                      behaviour related listeners                                        //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void setSharkCredentialReceivedListener(SharkCredentialReceivedListener listener) {
        this.checkStatus();
        this.credentialReceivedListener = listener;

        this.asapPeer.addASAPMessageReceivedListener(ASAPCertificateStore.CREDENTIAL_APP_NAME, this);
    }

    @Override
    public void asapMessagesReceived(ASAPMessages asapMessages,
                                     String senderE2E, // E2E part
                                     String senderPoint2Point, boolean verified, boolean encrypted, // Point2Point part
                                     EncounterConnectionType connectionType) throws IOException {
        if(this.credentialReceivedListener == null) {
            Log.writeLog(this, "received message but no listener - give up");
            return;
        }

        CharSequence uri = asapMessages.getURI();
        if(uri == null || !uri.toString().equalsIgnoreCase(SharkPKIComponent.CREDENTIAL_URI.toString())) {
            Log.writeLog(this, "received message but wrong uri: " + uri);
            return;
        }

        Iterator<byte[]> messages = asapMessages.getMessages();
        while (messages.hasNext()) {
            try {
                CredentialMessageInMemo credentialMessage = new CredentialMessageInMemo(messages.next());
                this.credentialReceivedListener.credentialReceived(credentialMessage);
            } catch (ASAPSecurityException e) {
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
                        "going to ask a peer to signing a certificate: " + peerID);
                try {
                    Log.writeLog(this, "create credential message");
                    CredentialMessage credentialMessage = this.createCredentialMessage();
                    Log.writeLog(this, "credential message == " + credentialMessage);
                    this.asapPeer.sendOnlineASAPMessage(ASAPCertificateStore.CREDENTIAL_APP_NAME,
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

    private FullAsapPKIStorage asapPKIStorage = null;
    private ASAPAbstractCertificateStore asapCertificateStorage;
    private ASAPPeer asapPeer = null;
    private ASAPKeyStore asapKeyStore = null;

    SharkPKIComponentImpl(ASAPKeyStore asapKeyStore) {
        this.asapKeyStore = asapKeyStore;
    }

    @Override
    public void onStart(ASAPPeer asapPeer) throws SharkException {
        this.asapPeer = asapPeer;
        try {
            ASAPStorage asapStorage = asapPeer.getASAPStorage(ASAPCertificateStorage.PKI_APP_NAME);
            this.asapCertificateStorage =
                new ASAPAbstractCertificateStore(asapStorage, asapPeer.getPeerID(), asapPeer.getPeerID());

            if(this.asapKeyStore == null) {
                this.asapKeyStore = new InMemoASAPKeyStore(asapPeer.getPeerID());
            }

            this.asapPKIStorage = new FullAsapPKIStorage(this.asapCertificateStorage, this.asapKeyStore);

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
        CredentialMessage credentialMessage = this.createCredentialMessage();
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

        // spread the news to all peers only
        try {
            this.asapPeer.sendOnlineASAPMessage(ASAPCertificateStorage.PKI_APP_NAME,
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
    public PersonValuesImpl getPersonValuesByPosition(int position) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPersonValuesByPosition(position);
    }

    @Override
    public PersonValues getPersonValuesByID(CharSequence peerID) throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.getPersonValues(peerID);
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
    public void addCertificate(ASAPCertificate asapCertificate) throws IOException, ASAPSecurityException {
        this.checkStatus();
        this.asapPKIStorage.addCertificate(asapCertificate);
    }

    @Override
    public boolean verifyCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        this.checkStatus();
        return this.asapPKIStorage.verifyCertificate(asapCertificate);
    }

    @Override
    public CredentialMessage createCredentialMessage() throws ASAPSecurityException {
        this.checkStatus();
        return this.asapPKIStorage.createCredentialMessage();
    }

    @Override
    public void sendOnlineCredentialMessage() throws ASAPException, IOException {
        this.checkStatus();
        CredentialMessage credentialMessage = this.createCredentialMessage();
        this.asapPeer.sendOnlineASAPMessage(
                SharkPKIComponent.CREDENTIAL_APP_NAME,
                SharkPKIComponent.CREDENTIAL_URI,
                credentialMessage.getMessageAsBytes());
    }

    @Override
    public boolean syncNewReceivedCertificates() {
        this.checkStatus();
        return this.asapPKIStorage.incorporateReceivedCertificates();
    }

    @Override
    public void store(OutputStream os) throws IOException {
        this.checkStatus();
        this.asapPKIStorage.store(os);
    }

    @Override
    public void load(InputStream is) throws IOException {
        this.checkStatus();
        this.asapPKIStorage.load(is);
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
