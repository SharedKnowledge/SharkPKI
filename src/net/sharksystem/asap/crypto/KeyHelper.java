package net.sharksystem.asap.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class KeyHelper {
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          key serialization                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static void writePublicKeyToStream(PublicKey publicKey, DataOutputStream dos) throws IOException {
        writeKeyToStream(publicKey, dos);
    }

    public static void writePrivateKeyToStream(PrivateKey privateKey, DataOutputStream dos) throws IOException {
        writeKeyToStream(privateKey, dos);
    }

    private static void writeKeyToStream(Key key, DataOutputStream dos) throws IOException {
        dos.writeUTF(key.getAlgorithm());
        byte[] pubKeyBytes = key.getEncoded();

        dos.writeInt(pubKeyBytes.length);
        dos.write(pubKeyBytes);
    }

    public static PublicKey readPublicKeyFromStream(DataInputStream dis)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Key key = readKeyFromStream(dis, true);
        return (PublicKey) key;
    }

    public static PrivateKey readPrivateKeyFromStream(DataInputStream dis)
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Key key = readKeyFromStream(dis, false);
        return (PrivateKey) key;
    }

    public static Key readKeyFromStream(DataInputStream dis, boolean createPublicKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String algorithm = dis.readUTF();
        int length = dis.readInt();
        byte[] keyBytes = new byte[length];
        dis.read(keyBytes);

        // decode public key
        KeyFactory keyFactory = null;
        keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);

        return createPublicKey ?
                keyFactory.generatePublic(x509EncodedKeySpec) : keyFactory.generatePrivate(x509EncodedKeySpec);
    }
}
