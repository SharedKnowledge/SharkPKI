package net.sharksystem.pki;

import net.sharksystem.asap.ASAPSecurityException;
import net.sharksystem.utils.Log;

import java.io.IOException;

class CredentialListenerSignsWithoutChecking implements SharkCredentialReceivedListener {
    private final SharkPKIComponent sharkPKIComponent;
    public int numberOfEncounter = 0;
    public CredentialMessage lastCredentialMessage;

    public CredentialListenerSignsWithoutChecking(SharkPKIComponent sharkPKIComponent) {
        this.sharkPKIComponent = sharkPKIComponent;
    }

    @Override
    public void credentialReceived(CredentialMessage credentialMessage) {
        Log.writeLog(this, this.sharkPKIComponent.getOwnerID(), "credential received:\n"
                + PKIHelper.credentialMessage2String(credentialMessage));
        try {
            /*
            Absolutely not. No! Automatically signing a credential message which simply came along from an unknown
            source is ridiculous. Never ever write an app like this. That's only for debugging. Only!
            Don't even think things like: "Em, well, I just take is for a temporary solution, just to
            illustrate that it works..." It works, alright. That is what this test is for.

            Taking it as 'temporary' solution is most probably BS and you know that. Deal with security from the
            beginning of your app development. Security is not anything you add 'sometimes later'. It is
            part of your app philosophy or not.
            You will make the world a better place by embracing security. :)

            It is important: Users must ensure correct data. Human users must ensure that those data are valid and
            the sending person is really who s/he claims to be.
             */
            this.numberOfEncounter++;
            this.lastCredentialMessage = credentialMessage;
            Log.writeLog(this, this.sharkPKIComponent.getOwnerID(), ">>>>>>>>>> DO THE UNDOABLE - ISSUE CERTIFICATE WITHOUT CHECKING USER IDENTITY");
            Log.writeLog(this, this.sharkPKIComponent.getOwnerID(), "going to issue a certificate");
            this.sharkPKIComponent.acceptAndSignCredential(credentialMessage);
        } catch (IOException | ASAPSecurityException e) {
            e.printStackTrace();
        }
    }
}
