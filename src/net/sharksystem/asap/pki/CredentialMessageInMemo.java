package net.sharksystem.asap.pki;

import net.sharksystem.asap.ASAPException;
import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.asap.utils.ASAPSerialization;
import net.sharksystem.asap.utils.DateTimeHelper;
import net.sharksystem.pki.CredentialMessage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

public class CredentialMessageInMemo implements CredentialMessage {
    private final long validSince;
    private CharSequence subjectID;
    private CharSequence subjectName;
    private int randomInt;
    private byte[] extraData;
    private PublicKey publicKey;

    public CharSequence getSubjectID() { return this.subjectID; }
    public CharSequence getSubjectName() { return this.subjectName; }
    public int getRandomInt() { return this.randomInt; }
    public long getValidSince() { return this.validSince; }
    public byte[] getExtraData() { return this.extraData; }
    public PublicKey getPublicKey() { return this.publicKey; }

    public CredentialMessageInMemo(CharSequence subjectID, CharSequence subjectName,
                   long validSince, PublicKey publicKey) {
        this(subjectID, subjectName, validSince, publicKey, null);
    }

    public CredentialMessageInMemo(CharSequence subjectID, CharSequence subjectName,
                   long validSince, PublicKey publicKey, byte[] extraData) {
        this.subjectID = subjectID;
        this.subjectName = subjectName;
        this.validSince = validSince;
        this.extraData = extraData;
        this.publicKey = publicKey;

        int randomStart = ((new Random(System.currentTimeMillis())).nextInt());

        // make it positiv
        if(randomStart < 0) randomStart = 0-randomStart;

        // take 6 digits
        int sixDigitsInt = 0;
        for(int i = 0; i < 6; i++) {
            sixDigitsInt += randomStart % 10;
            sixDigitsInt *= 10;
            randomStart /= 10;
        }

        sixDigitsInt /= 10;

        this.randomInt = sixDigitsInt;
    }

    public CredentialMessageInMemo(byte[] serializedMessage) throws IOException, ASAPException {
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedMessage);
        DataInputStream dis = new DataInputStream(bais);

        this.subjectID = dis.readUTF();
        this.subjectName = dis.readUTF();
        this.randomInt = dis.readInt();
        this.validSince = dis.readLong();
        this.extraData = ASAPSerialization.readByteArray(bais);
        if(this.extraData != null && this.extraData.length < 1) this.extraData = null;

        // public key
        String algorithm = dis.readUTF(); // read public key algorithm
        int length = dis.readInt(); // read public key length
        byte[] publicKeyBytes = new byte[length];
        dis.read(publicKeyBytes); // read public key bytes

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(algorithm);
            this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (Exception e) {
            throw new ASAPSecurityException(e.getLocalizedMessage());
        }
    }

    /**
     * Serialize
     * @return
     * @throws IOException
     */
    public byte[] getMessageAsBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeUTF(this.subjectID.toString());
        dos.writeUTF(this.subjectName.toString());
        dos.writeInt(this.randomInt);
        dos.writeLong(this.validSince);
        ASAPSerialization.writeByteArray(this.extraData, baos);

        // public key
        dos.writeUTF(this.publicKey.getAlgorithm()); // write public key algorithm

        byte[] publicKeyBytes = this.publicKey.getEncoded();
        dos.writeInt(publicKeyBytes.length); // write public key length
        dos.write(publicKeyBytes); // write public key bytes

        return baos.toByteArray();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("name: ");
        sb.append(this.subjectName);
        sb.append(" | ");

        sb.append("id: ");
        sb.append(this.subjectID);
        sb.append(" | ");

        sb.append("valid since: ");
        sb.append(DateTimeHelper.long2DateString(this.validSince));
        sb.append(" | ");

        sb.append("randInt: ");
        sb.append(this.randomInt);
        sb.append(" | ");

        sb.append("#extra byte: ");
        if(this.extraData == null || this.extraData.length < 1) {
            sb.append("0");
        } else {
            sb.append(this.extraData.length);
        }
        sb.append(" | ");

        sb.append("publicKey: ");
        sb.append(this.publicKey);

        return sb.toString();
    }
}
