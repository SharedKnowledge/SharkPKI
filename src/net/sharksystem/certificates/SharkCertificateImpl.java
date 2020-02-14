package net.sharksystem.certificates;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Calendar;

public class SharkCertificateImpl implements SharkCertificate {
    public static final int DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS = 1;
    public static final String DEFAULT_SIGNATURE_METHOD = "SHA256withRSA";

    private final PublicKey publicKey;
    private final CharSequence ownerName;
    private final int ownerID;
    private final CharSequence signerName;
    private final int signerID;
    private final byte[] signatureBytes;
    private Calendar validSince;
    private Calendar validUntil;

    public SharkCertificateImpl(int signerID,
                                CharSequence signerName,
                                PrivateKey privateKey,
                                int ownerID, CharSequence ownerName,
                                PublicKey publicKey) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        this.signerID = signerID;
        this.signerName = signerName;
        this.ownerID = ownerID;
        this.ownerName = ownerName;
        this.publicKey = publicKey;

        this.validSince = Calendar.getInstance();
        this.validUntil = Calendar.getInstance();
        this.validUntil.add(Calendar.YEAR, DEFAULT_CERTIFICATE_VALIDITY_IN_YEARS);

        // create signature
        Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_METHOD);
        signature.initSign(privateKey, new SecureRandom()); // TODO: should use a seed
        signature.update(this.getAnythingButSignatur());
        this.signatureBytes = signature.sign();
    }

    private byte[] getAnythingButSignatur() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);
        this.fillWithAnythingButSignature(daos);
        return baos.toByteArray();
    }

    private void fillWithAnythingButSignature(DataOutputStream daos) {
        // create byte array that is to be signed
        try {
            daos.writeInt(this.signerID);
            daos.writeUTF(this.signerName.toString());
            daos.writeInt(this.ownerID);
            daos.writeUTF(this.getOwnerName().toString());

            daos.writeLong(this.validSince.getTimeInMillis());
            daos.writeLong(this.validUntil.getTimeInMillis());

            byte[] pubKeyBytes = this.publicKey.getEncoded();

            daos.writeInt(pubKeyBytes.length);
            daos.write(pubKeyBytes);
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
        }

        return baos.toByteArray();
    }

    @Override
    public boolean verify(PublicKey publicKeyIssuer) throws NoSuchAlgorithmException {
        Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_METHOD);

        try {
            signature.initVerify(publicKeyIssuer);
            signature.update(this.getAnythingButSignatur());
            return signature.verify(this.signatureBytes);
        }
        catch(Exception e) {
            return false;
        }
    }

    @Override
    public int getOwnerID() { return this.ownerID; }

    @Override
    public CharSequence getOwnerName() { return this.ownerName; }

    @Override
    public CharSequence getSignerName() {  return this.signerName;  }

    @Override
    public int getSignerID() { return this.signerID; }

    @Override
    public Calendar getValidSince() { return this.validSince; }

    @Override
    public Calendar getValidUntil() { return this.validUntil; }
}
