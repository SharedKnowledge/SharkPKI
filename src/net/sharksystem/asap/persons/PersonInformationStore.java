package net.sharksystem.asap.persons;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.fs.ExtraData;
import net.sharksystem.pki.CredentialMessage;

import java.io.IOException;
import java.security.*;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * This storage provides some information and methods:
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
 * One final thing: There is no addPerson() or addPeer method in this component. There is only one way to add
 * a peer (person) to th list: By creating a certificate or by receiving an existing certificate.
 */
public interface PersonInformationStore {
    String CREDENTIAL_APP_NAME = "SharkCredentials";
    CharSequence CREDENTIAL_URI = "asapShark://credential";

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
//    PrivateKey getPrivateKey() throws ASAPSecurityException;

    /**
     * @return Public Key. There is no need to exchange this key in order to produce a certificate. There are better
     * ways
     * @throws ASAPSecurityException
     * @see CredentialMessage
     * @see #createCredentialMessage()
     */
//    PublicKey getPublicKey() throws ASAPSecurityException;

    /**
     * @return time when key are created
     */
//    long getKeysCreationTime() throws ASAPSecurityException;

    /**
     * Use this message if your application received a public key and has ensured senders' identity. This
     * method will create a certificate with your as issuer and user as subject. This certificate is
     * store and disseminate by this component to other peer using the same component.
     * <br/>
     * This message is the most essential part of any PKI. Ensuring identity is the very basic on which a
     * secure systems stands or fails. Be careful.
     *
     * @param userID subject ide
     * @param userName subject name
     * @param publicKey subjects' public key
     * @param validSince define a valid since moment. What about now? (System.currentTimeMillis())
     * @return
     * @throws ASAPSecurityException
     * @throws IOException
     */
//    ASAPCertificate addAndSignPerson(CharSequence userID, CharSequence userName, PublicKey publicKey, long validSince)
//            throws ASAPSecurityException, IOException;

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
    PersonValues getPersonValuesByPosition(int position) throws ASAPSecurityException;

    PersonValues getPersonValuesByID(CharSequence personID) throws ASAPSecurityException;

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
     * @return best identity assurance or 10 if no assurance at all
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

    Set<ASAPCertificate> getAllCertificates();

    /**
     * Add a certificate to this storage. That method is used to store an already existing certificate. There are
     * rary circumstances in which an application needs this method. Certificates are exchange automatically by this
     * component. A new certificate can be produced by another method
     * //@see #addAndSignPerson(CharSequence, CharSequence, PublicKey, long)
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
     * @see #CREDENTIAL_APP_NAME
     * @see #CREDENTIAL_URI
     */
    CredentialMessage createCredentialMessage() throws ASAPSecurityException;

    /**
     * Call this method if probably new certificates are received
     * @return true if certificate of a new person received - time to call store.
     */
    boolean incorporateReceivedCertificates();

    CredentialMessage createCredentialMessage(byte[] extraData) throws ASAPSecurityException;

    void setMementoTarget(ExtraData extraData);
}