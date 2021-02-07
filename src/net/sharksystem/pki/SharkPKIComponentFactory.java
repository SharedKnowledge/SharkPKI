package net.sharksystem.pki;

import net.sharksystem.SharkComponent;
import net.sharksystem.SharkComponentFactory;
import net.sharksystem.asap.crypto.ASAPKeyStore;

public class SharkPKIComponentFactory implements SharkComponentFactory {
    private ASAPKeyStore asapKeyStore;
    private SharkPKIComponentImpl instance = null;

    public SharkPKIComponentFactory() {};
    public SharkPKIComponentFactory(ASAPKeyStore asapKeyStore) {
        this.asapKeyStore = asapKeyStore;
    };

    @Override
    public SharkComponent getComponent() {
        if(this.instance == null) {
            this.instance = new SharkPKIComponentImpl(this.asapKeyStore);
        }

        return this.instance;
    }
}
