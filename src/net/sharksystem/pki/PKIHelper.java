package net.sharksystem.pki;

import net.sharksystem.asap.persons.PersonValues;
import net.sharksystem.asap.persons.PersonValuesImpl;
import net.sharksystem.asap.pki.ASAPCertificate;
import net.sharksystem.asap.utils.DateTimeHelper;

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
        sb.append(net.sharksystem.utils.Utils.calendar2String(certificate.getValidSince()));
        sb.append("\nvalid until: ");
        sb.append(net.sharksystem.utils.Utils.calendar2String(certificate.getValidUntil()));

        return sb.toString();
    }

    public static String credentialMessage2String(CredentialMessage credentialMessage) {
        StringBuilder sb = new StringBuilder();
        sb.append("send from potential subject: ");
        sb.append("id: ");
        sb.append(credentialMessage.getSubjectID());
        sb.append(" | ");
        sb.append("name: ");
        sb.append(credentialMessage.getSubjectName());
        sb.append("\nproposed valid since: ");
        sb.append(DateTimeHelper.long2DateString(credentialMessage.getValidSince()));
        sb.append("\nrandom number: ");
        sb.append(credentialMessage.getRandomInt());
        sb.append("\nTODO - add public key fingerprint (project SharPKI (net.sharksystem.pki.PKIHelper)");

        return sb.toString();
    }

    public static String personalValue2String(PersonValues personValues) {
        if(personValues == null) return "null";

        StringBuilder sb = new StringBuilder();
        sb.append("id: ");
        sb.append(personValues.getUserID());
        sb.append(" | ");
        sb.append("name: ");
        sb.append(personValues.getName());
        sb.append(" | ");
        sb.append("iA: ");
        //sb.append(personValues.getIdentityAssurance());
        sb.append(" TODO ");
        sb.append(" | ");
        sb.append("sf: ");
        sb.append(personValues.getSigningFailureRate());

        return sb.toString();
    }
}
