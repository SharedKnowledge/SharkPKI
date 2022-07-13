package net.sharksystem.pki;

import net.sharksystem.ASAPFormats;
import net.sharksystem.SharkComponent;
import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.persons.PersonValues;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.pki.ASAPCertificateStorage;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.persons.ASAPCertificateStore;
import net.sharksystem.asap.persons.PersonValuesImpl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Collection;
import java.util.List;

/**
 * This component provides several information and methods:
 *
 * <ul>
 *     <li>A list of peers (actually real persons which are assumed to be owners of an encountered peer (device))</li>
 *     <li>A storage of certificates</li>
 *     <li>means to create a new certificate</li>
 *     <li>means to send public key and some other information to ask another peer for certification</li>
 *     <li>Methods to display information relevant for this PIK</li>
 *     <li>The component also allows to estimate a failure rate of peers during the signing process. This
 *     estimation is used to calculate an identity assurance, see Wiki of this component for details.</li>
 * </ul>
 * <br/>
 * See <a href="https://github.com/SharedKnowledge/ASAPCertificateExchange/wiki">Wiki of this component
 * for more details and explanations</a>.
 * <br/>
 * You should use specific interfaces for specific tasks to make your code clearer, e.g.
 * <br/><br/>
 * <code>SharkPeer sPeer = ...;</code><br/>
 * <code>SharkCertificateComponent component = sPeer.getComponent(SharkCertificateComponent.class);</code><br/>
 * <code>// use a specific interface</code><br/>
 * <code>ASAPKeyStore asapKeyStore = component;</code><br/>
 * <code>SharkCertificateComponent cerComponent = component;</code><br/>
 * <br/>
 *
 * <ul>
 *     <li>Use <a href="http://sharksystem.net/asap/javadoc/net/sharksystem/asap/crypto/ASAPKeyStore.html">ASAPKeyStore</a>
 *     interface to manage key of this local peer.</li>
 *     <li>Use ASAPCertificateStore for certificate management and creation.</li>
 * </ul>
 * <br/>
 * Have a look in the test folder. There are usage examples which can in most cases uses in a cut&paste manner.
 *
 * @see SharkPKIComponent
 */

@ASAPFormats(formats = {SharkPKIComponent.CREDENTIAL_APP_NAME, SharkPKIComponent.PKI_APP_NAME})
public interface SharkPKIComponent extends SharkComponent, ASAPKeyStore {
    CharSequence CREDENTIAL_URI = "sn2://credential";
    String PKI_APP_NAME = ASAPCertificateStorage.PKI_APP_NAME;
    String CREDENTIAL_APP_NAME = ASAPCertificateStore.CREDENTIAL_APP_NAME;

    /**
     * Peers can ask each other to sign their public keys. This process can be automated by setting this
     * flag on. In that case, this component would automatically send a credential message
     * (a message containing peer id, public key, time of key creation). The other peer should have implemented
     * a listener for a proper reaction.
     * <br/>
     * This behaviour can also be made by an application itself. It could listen to newly arrived peer with the
     * ASAPPeer and send a message. This component offers a method to produce a credential message.
     * <br/>
     * Default behaviour is off.
     * @see #createCredentialMessage()
     */
    String BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER = "certComponent_sendCredentialFirstEncounter";

    /**
     * Peers can send a credential message. This process can be automated by setting an flag. Anyway, your application
     * must deal with it. That is probably the most essential part of your application when it comes to security.
     * Users (human users! under no, repeated: under no, circumstances a machine) must ensure the identity of the
     * person that transmitted that message with its peer. Read, an really please read and consider our documentation:
     * <a href="https://github.com/SharedKnowledge/ASAPCertificateExchange/wiki#signing">Signing</a>
     * <br/>Create a certificate if users of your application are doubtlessly ensure correctness of identity of the
     * sending person.
     * @param listener an object that runs this very crucial algorithm
     * @see #acceptAndSignCredential(CredentialMessage)
     */
    void setSharkCredentialReceivedListener(SharkCredentialReceivedListener listener);


    /**
     * Use this method to issue a new certificate based on a received message.
     * Users (human users! under no, repeated: under no, circumstances a machine) must ensure the identity of the
     * person that transmitted that message with its peer. Read, an really please read and consider our documentation:
     * <a href="https://github.com/SharedKnowledge/ASAPCertificateExchange/wiki#signing">Signing</a>
     * <br/>Create a certificate if users of your application are doubtlessly ensure correctness of identity of the
     * sending person.
     *
     * @param credentialMessage message for which your are going to sign and disseminate a certificate for. Be careful!
     *                         Your reputation as developer and reputation of your users are on stake here.
     * @return created certificate. You do not have to deal with it. This component automatically exchanges certificate.
     * @throws ASAPSecurityException
     * @throws IOException
     */
    ASAPCertificate acceptAndSignCredential(CredentialMessage credentialMessage) throws IOException, ASAPSecurityException;

    /**
     * Create a new key pair. Old one is removed
     */
    void createNewKeyPair() throws ASAPException, IOException;

    /*
    ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince)
            throws ASAPSecurityException, IOException;
     */

    /**
     *
     * @return owner id of this certificate storage. It will be most probably the local peer.
     */
    CharSequence getOwnerID();

    /**
     * @return owner name of this certificate storage. It will be most probably the local peer.
     */
    CharSequence getOwnerName();


    /**
     * @return Private key of this local peer the local peer. Never, under no circumstances, store or sent this
     * information to anybody else. Even existence of this method could be seen as a security risc. It is your
     * app. It shall be safe. Persistent storage of key is the keystore which is platform specific.
     */
    PrivateKey getPrivateKey() throws ASAPSecurityException;

    /**
     * @return Public Key. There is no need to exchange this key in order to produce a certificate. There are better
     * ways
     * @throws ASAPSecurityException
     * @see CredentialMessage
     * @see #createCredentialMessage()
     */
    PublicKey getPublicKey() throws ASAPSecurityException;

    /**
     * @return time when key are created
     */
    long getKeysCreationTime() throws ASAPSecurityException;

    /**
     * Set failure rate estimation of this local of the other peer.
     * @param personID peers' id which failure rate is estimated
     * @param failureRate 1 .. 10 (10% .. 100%).
     * @throws ASAPSecurityException
     */
    void setSigningFailureRate(CharSequence personID, int failureRate) throws ASAPSecurityException;

    /**
     * @param personID
     * @return estimated failure rate of this peer. That information should remain only visible to the peer that
     * made this estimation. There is no need to reveal it to others. This method should only be used for a GUI
     * not for any exchange.
     */
    int getSigningFailureRate(CharSequence personID);

    /**
     * This component keeps an ordered list of known peers
     * (or more precisely their owner which are considered to be persons).
     *
     * This method comes in handy when implementing a recycler view in Android.
     *
     * @param position non-negative value
     * @return Information of person at position
     * @throws ASAPSecurityException
     */
    PersonValuesImpl getPersonValuesByPosition(int position) throws ASAPSecurityException;

    /**
     * Get information about a peer by id
     * @param peerID
     * @return
     * @throws ASAPSecurityException if no peer found with this id
     */
    PersonValues getPersonValuesByID(CharSequence peerID) throws ASAPSecurityException;

    /**
     * This component keeps an ordered list of known peers
     * (or more precisely their owner which are considered to be persons).
     *
     * @return Number if known persons (without local peer)
     */
    int getNumberOfPersons();

    /**
     * Identity assurance is calculated by a chain of certificate. See Github Wiki for details.
     * @param userID
     * @return best identity assurance or 10 if no assurance at all, maybe not met before
     * @throws ASAPSecurityException
     */
    int getIdentityAssurance(CharSequence userID) throws ASAPSecurityException;

    /**
     * Identity assurance is calculated by a chain of certificate. See Github Wiki for details.
     *
     * @param userID
     * @return List of issuerIDs. Those peer issued certificates and form a chain that allows identifying peers
     * certificate. This information is not meant to be shared but only to be shown on a GUI to the user.
     * @param userID
     * @throws ASAPSecurityException
     */
    List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID)
            throws ASAPSecurityException;

    /**
     * @param subjectID peer id
     * @return all certificates issued for this peer (subject)
     * @throws ASAPSecurityException
     */
    Collection<ASAPCertificate> getCertificatesBySubject(CharSequence subjectID) throws ASAPSecurityException;

    /**
     * @param issuerID
     * @return all certificates issued by this peer.
     * @throws ASAPSecurityException
     */
    Collection<ASAPCertificate> getCertificatesByIssuer(CharSequence issuerID) throws ASAPSecurityException;
    ASAPCertificate getCertificateByIssuerAndSubject(CharSequence issuerID, CharSequence subjectID)
            throws ASAPSecurityException;

    /**
     * Add a certificate to this storage. That method is used to store an already existing certificate. There are
     * rare circumstances in which an application needs this method. Certificates are exchange automatically by this
     * component.
     * @param asapCertificate
     * @throws IOException
     * @throws ASAPSecurityException
     */
    void addCertificate(ASAPCertificate asapCertificate) throws IOException, ASAPSecurityException;

    /**
     * It is assumed this certificate is issued by storage owner. This is verified with this method or not.
     * That method is more for debugging purpose. It is used inside when re-reading certificates from external storage
     * to prevent security breeches.
     * class to assure thaty
     * @param asapCertificate
     * @throws IOException
     * @throws ASAPSecurityException
     */
    boolean verifyCertificate(ASAPCertificate asapCertificate) throws ASAPSecurityException, NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    /**
     * A credential message contains public key, peer id an name of this local peer. This message can be sent to
     * another peer to ask for certification of those information. Use defined format and uri for that message.
     * @return message that can be sent
     * @throws ASAPSecurityException
     * @see ASAPCertificateStore#CREDENTIAL_APP_NAME
     * @see #CREDENTIAL_URI
     */
    CredentialMessage createCredentialMessage() throws ASAPSecurityException;

    /**
     * Create a credential message including extra data. Those data are opaque to this
     * library and can be used by an application to add security features.
     * @param extraData
     * @return
     * @throws ASAPSecurityException
     */
    CredentialMessage createCredentialMessage(byte[] extraData) throws ASAPSecurityException;

    /**
     * Send a credential message to all peers which are actually in the neighbourhood. This method
     * is not needed, though. You should consider setting the appropriate behaviour to allow this component
     * to send a credential message as soon as it encounters another peers.
     *
     * Anyway, those messages can get lost. In that case: Call this method. Created credential message will
     * not be stored with the local storage nor re-sent. It is sent (with best-effort) and dropped afterwards.
     *
     * @throws ASAPSecurityException
     * @throws IOException
     * @see #BEHAVIOUR_SEND_CREDENTIAL_FIRST_ENCOUNTER
     */
    void sendOnlineCredentialMessage() throws ASAPException, IOException;

    /**
     * TODO
     * @param credentialMessage
     * @throws ASAPException
     * @throws IOException
     */
    void sendOnlineCredentialMessage(CredentialMessage credentialMessage) throws ASAPException, IOException;

    /**
     * Call this method if probably new certificates are received
     * @return true if certificate of a new person received - time to call store.
     */
    boolean syncNewReceivedCertificates();

    /**
     * Store content of this component into an external medium.
     * @param os
     * @throws IOException
     */
    void store(OutputStream os) throws IOException;

    /**
     * Recreate this component from an external medium.
     * @param os
     * @throws IOException
     */
    void load(InputStream os) throws IOException;
}
