package net.sharksystem.pki;

import net.sharksystem.SharkComponent;
import net.sharksystem.SharkComponentFactory;
import net.sharksystem.asap.crypto.ASAPKeyStore;

public class SharkPKIComponentFactory implements SharkComponentFactory {
    private final CharSequence peerName;
    private ASAPKeyStore asapKeyStore;
    private SharkPKIComponentImpl instance = null;

    public SharkPKIComponentFactory() {
        this(null, null);
    }

    public SharkPKIComponentFactory(ASAPKeyStore asapKeyStore) {
        this(asapKeyStore, null);
    }

    public SharkPKIComponentFactory(ASAPKeyStore asapKeyStore, CharSequence peerName)
    {
        this.asapKeyStore = asapKeyStore;
        this.peerName = peerName;
    };

    @Override
    public SharkComponent getComponent() {
        if(this.instance == null) {
            if(this.peerName == null) {
                this.instance = new SharkPKIComponentImpl(this.asapKeyStore);
            } else {
                this.instance = new SharkPKIComponentImpl(this.asapKeyStore, this.peerName);
            }
        }

        return this.instance;
    }
}
