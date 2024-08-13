package net.sharksystem.pki;

import net.sharksystem.asap.pki.ASAPCertificate;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class PKIHelper {
    public static String sixDigitsToString(int sixDigitsInt) {
        // give it a nice shape
        StringBuilder sb = new StringBuilder();
        for(int i = 5; i > -1; i--) {
            if(i % 2 == 1 && i != 5) sb.append(' ');

            int q = (int) Math.pow(10, i);
            int digit = sixDigitsInt / q;
            sixDigitsInt -= digit * q;

            sb.append(digit);
        }

        return sb.toString();
    }

    public static String asapCert2String(ASAPCertificate certificate) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS z");

        StringBuilder sb = new StringBuilder();
        sb.append("issued from: ");
        sb.append("id: ");
        sb.append(certificate.getIssuerID());
        sb.append(" | ");
        sb.append("name: ");
        sb.append(certificate.getIssuerName());
        sb.append("\nfor subject: ");
        sb.append("id: ");
        sb.append(certificate.getSubjectID());
        sb.append(" | ");
        sb.append("name: ");
        sb.append(certificate.getSubjectName());
        sb.append("\nvalid since: ");
        sb.append(dateFormat.format(certificate.getValidSince().getTime()));
        sb.append("\nvalid until: ");
        sb.append(dateFormat.format(certificate.getValidUntil().getTime()));

        return sb.toString();
    }
}
