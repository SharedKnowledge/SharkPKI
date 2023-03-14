package net.sharksystem.asap.pki;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.persons.ASAPCertificateStore;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

public interface ASAPCertificateStorage {
    String PKI_APP_NAME = "ASAPSharkCertificates";

    /**
     *
     * @param subjectID
     * @return collection of certificates of a given subject
     */
    Collection<ASAPCertificate> getCertificatesBySubjectID(CharSequence subjectID);

    /**
     * @param issuerID
     * @return collection of certificates signed by an issuer
     */
    Collection<ASAPCertificate> getCertificatesByIssuerID(CharSequence issuerID);

    /**
     * @param issuerID
     * @param subjectID
     * @return collection of certificates signed by an issuer for subjectID
     */
    ASAPCertificate getCertificateByIssuerAndSubjectID(
            CharSequence issuerID, CharSequence subjectID) throws ASAPSecurityException;

    /**
     *
     * @return a collection of certificates in which the owner of this storage is subject.
     * In other words: All certificates issued by others than the owner which proof connection of it identity with
     * its public key
     */
    Collection<ASAPCertificate> getCertificatesForOwnerSubject();

    /**
     * @return collection of certificates retrieved since certificate storage was set up
     */
    Collection<ASAPCertificate> getNewReceivedCertificates();

    /**
     *
     * @return owner id
     */
    CharSequence getOwnerID();

    /**
     *
     * @return owner name
     */
    CharSequence getOwnerName();

    /**
     * Store a certificate with an asap storage
     * @param asapCertificate
     * @return
     * @throws IOException
     */
    ASAPStorageAddress storeCertificate(ASAPCertificate asapCertificate) throws IOException;

    void removeCertificate(ASAPCertificate cert2remove) throws IOException;
    void removeCertificate(Collection<ASAPCertificate> certs2remove) throws IOException;

    /**
     * recalculate identity assurance based on present and valid certificates
     */
    void syncIdentityAssurance();

    /**
     *
     * @return current era of asap storage holding those certificates
     */
    int getEra();

    /**
     * sync memory with potential external changes
     */
    void dropInMemoCache();

    int getIdentityAssurances(CharSequence userID, ASAPCertificateStore ASAPCertificateStore) throws ASAPSecurityException;

    List<CharSequence> getIdentityAssurancesCertificationPath(CharSequence userID, ASAPCertificateStore ASAPCertificateStore)
            throws ASAPSecurityException;

    ASAPStorageAddress getASAPStorageAddress(byte[] serializedAddress) throws IOException;
}
