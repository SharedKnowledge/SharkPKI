package net.sharksystem.asap.crypto;

import net.sharksystem.asap.util.DateTimeHelper;
import net.sharksystem.asap.util.Log;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;

public class ASAPCertificateImpl implements ASAPCertificate {
    public static final int DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS = 1;
    public static final String DEFAULT_SIGNATURE_METHOD = "SHA256withRSA";

    private PublicKey publicKey;
    private CharSequence subjectName;
    private CharSequence subjectID;
    private CharSequence issuerName;
    private CharSequence issuerID;
    private byte[] signatureBytes;
    private ASAPStorageAddress asapStorageAddress;
    private long validSince;
    private long validUntil;
    private String signingAlgorithm;

    /**
     * Create fresh certificate for owner and sign it now with signers private key.
     * @param issuerID
     * @param issuerName
     * @param privateKey
     * @param subjectID
     * @param subjectName
     * @param publicKey
     * @return
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     */
    public static ASAPCertificateImpl produceCertificate(
            CharSequence issuerID, CharSequence issuerName,
            PrivateKey privateKey,
            CharSequence subjectID, CharSequence subjectName,
            PublicKey publicKey,
            long validSince,
            CharSequence signingAlgorithm)
                throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

        // must be in the past to avoid key not yet valid exception
        long now = System.currentTimeMillis();

        if(validSince > now) {
            Log.writeLog(ASAPCertificateImpl.class, "valid since must be in past - set to now");
            validSince = now;
        }

        Calendar since = Calendar.getInstance();
        since.setTimeInMillis(validSince);
        since.add(Calendar.MINUTE, -1);

        Calendar until = Calendar.getInstance();
        until.setTimeInMillis(validSince);
        until.add(Calendar.YEAR, DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS);

        Log.writeLog(ASAPCertificateImpl.class, "issuerID: " + issuerID);
        Log.writeLog(ASAPCertificateImpl.class, "issuerName: " + issuerName);
        Log.writeLog(ASAPCertificateImpl.class, "privateKey: " + privateKey);
        Log.writeLog(ASAPCertificateImpl.class, "subjectID: " + subjectID);
        Log.writeLog(ASAPCertificateImpl.class, "subjectName: " + subjectName);
        Log.writeLog(ASAPCertificateImpl.class, "publicKey: " + publicKey);
        Log.writeLog(ASAPCertificateImpl.class, "since: " + DateTimeHelper.long2DateString(since.getTimeInMillis()));
        Log.writeLog(ASAPCertificateImpl.class, "until: " + DateTimeHelper.long2DateString(until.getTimeInMillis()));

        Log.writeLog(ASAPCertificateImpl.class, "now: " + DateTimeHelper.long2DateString(now));

        ASAPCertificateImpl asapCertificate = new ASAPCertificateImpl(
                issuerID, issuerName, subjectID, subjectName, publicKey, since.getTimeInMillis(),
                until.getTimeInMillis(), signingAlgorithm);

        asapCertificate.sign(privateKey);

        return asapCertificate;
    }

    private ASAPCertificateImpl(CharSequence issuerID,
                                CharSequence issuerName,
                                CharSequence subjectID, CharSequence subjectName,
                                PublicKey publicKey, long validSince, long validUntil,
                                CharSequence signingAlgorithm) {
        this.issuerID = issuerID;
        this.issuerName = issuerName;
        this.subjectID = subjectID;
        this.subjectName = subjectName;
        this.publicKey = publicKey;

        this.validSince = validSince;
        this.validUntil = validUntil;

        this.signingAlgorithm = signingAlgorithm.toString();
    }

    void setASAPStorageAddress(ASAPStorageAddress asapStorageAddress) {
        this.asapStorageAddress = asapStorageAddress;
    }

    private void sign(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // create signature
//        Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_METHOD);
        Log.writeLog(this, "try to get signature object...");
        Signature signature = Signature.getInstance(this.signingAlgorithm);
        Log.writeLog(this, "...got signature object: " + signature);
        Log.writeLog(this, "going to initialize signature object.... ");
//        signature.initSign(privateKey, new SecureRandom()); // TODO: should use a seed
        signature.initSign(privateKey); // desperate try
        Log.writeLog(this, "...initialized. Going to feed signature with text to sign..." + signature);
        signature.update(this.getAnythingButSignatur());
        Log.writeLog(this, "...updated signature object, going to sign...");
        this.signatureBytes = signature.sign();
        Log.writeLog(this, "..got signature. done." + signature);
    }

    @Override
    public boolean verify(PublicKey publicKeyIssuer) throws NoSuchAlgorithmException {
//        Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_METHOD);
        Signature signature = Signature.getInstance(this.signingAlgorithm);
        Log.writeLog(this, "got signature object: " + signature);

        try {
            signature.initVerify(publicKeyIssuer);
            Log.writeLog(this, "got signature object for verifying: " + signature);
            signature.update(this.getAnythingButSignatur());
            Log.writeLog(this, "updated signature object");
            boolean verified = signature.verify(this.signatureBytes);
            Log.writeLog(this, "verified: " + verified);
            return verified;
        }
        catch(Exception e) {
            Log.writeLogErr(this, "exception during verification:  " + e.getLocalizedMessage());
            return false;
        }
    }

    public static ASAPCertificateImpl produceCertificateFromBytes(
            byte[] serializedMessage)
                throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        ByteArrayInputStream bais = new ByteArrayInputStream(serializedMessage);
        DataInputStream dis = new DataInputStream(bais);

        String signerID = dis.readUTF();
        String signerName = dis.readUTF();
        String ownerID = dis.readUTF();
        String ownerName = dis.readUTF();
        long validSince = dis.readLong();
        long validUntil = dis.readLong();
        String signingAlgorithm = dis.readUTF();

        // read public key
        PublicKey pubKey = KeyHelper.readPublicKeyFromStream(dis);

        int length = dis.readInt();
        byte[] signatureBytes = new byte[length];
        dis.read(signatureBytes);

        ASAPCertificateImpl asapCertificate = new ASAPCertificateImpl(
                signerID, signerName, ownerID, ownerName, pubKey, validSince, validUntil, signingAlgorithm);

        asapCertificate.signatureBytes = signatureBytes;

        return asapCertificate;
    }

    public static ASAPCertificateImpl produceCertificateFromByteArray(
            byte[] serializedMessage, ASAPStorageAddress asapStorageAddress)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        ASAPCertificateImpl asapCertificate = ASAPCertificateImpl.produceCertificateFromBytes(serializedMessage);

        asapCertificate.asapStorageAddress = asapStorageAddress;

        return asapCertificate;
    }

    private byte[] getAnythingButSignatur() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);
        this.fillWithAnythingButSignature(daos);
        return baos.toByteArray();
    }

    private void fillWithAnythingButSignature(DataOutputStream dos) {
        // create byte array that is to be signed
        try {
            dos.writeUTF(this.issuerID.toString());
            dos.writeUTF(this.issuerName.toString());
            dos.writeUTF(this.subjectID.toString());
            dos.writeUTF(this.getSubjectName().toString());

            dos.writeLong(this.validSince);
            dos.writeLong(this.validUntil);
            dos.writeUTF(this.signingAlgorithm);

            // public key serialization
            KeyHelper.writePublicKeyToStream(this.publicKey, dos);

            /*
            dos.writeUTF(this.publicKey.getAlgorithm());
            byte[] pubKeyBytes = this.publicKey.getEncoded();

            dos.writeInt(pubKeyBytes.length);
            dos.write(pubKeyBytes);
             */
        }
        catch (IOException ioe) {
            // cannot happen - really
        }
    }

    public byte[] asBytes() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);

        this.fillWithAnythingButSignature(daos);

        try {
            daos.writeInt(this.signatureBytes.length);
            daos.write(this.signatureBytes);
        } catch (IOException e) {
            // cannot happen - really
            Log.writeLogErr(this, "could not happen but did while serializing a certificate (ignored): "
                    + e.getLocalizedMessage());
        }

        return baos.toByteArray();
    }

    @Override
    public ASAPStorageAddress getASAPStorageAddress() {
        return this.asapStorageAddress;
    }

    @Override
    public CharSequence getSubjectID() { return this.subjectID; }

    @Override
    public CharSequence getSubjectName() { return this.subjectName; }

    @Override
    public CharSequence getIssuerName() {  return this.issuerName;  }

    @Override
    public CharSequence getIssuerID() { return this.issuerID; }

    public static Calendar long2Calendar(long timeInMillis) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(timeInMillis);
        return calendar;
    }

    @Override
    public Calendar getValidSince() { return long2Calendar(this.validSince); }

    @Override
    public Calendar getValidUntil() { return long2Calendar(this.validUntil); }

    public PublicKey getPublicKey() { return this.publicKey; }

    @Override
    public boolean isIdentical(ASAPCertificate cert) {
        return this.getSubjectID().toString().equalsIgnoreCase(cert.getSubjectID().toString())
                && this.getIssuerID().toString().equalsIgnoreCase(cert.getIssuerID().toString())
                && this.getValidSince().getTimeInMillis() == cert.getValidSince().getTimeInMillis()
                && this.getValidUntil().getTimeInMillis() == cert.getValidUntil().getTimeInMillis()
                && this.getPublicKey().toString().equalsIgnoreCase(cert.getPublicKey().toString()
        );
    }
}
