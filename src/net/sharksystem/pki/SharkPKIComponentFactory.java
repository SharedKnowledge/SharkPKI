package net.sharksystem.pki;

import net.sharksystem.SharkComponent;
import net.sharksystem.SharkComponentFactory;
import net.sharksystem.SharkException;
import net.sharksystem.SharkPeer;
import net.sharksystem.asap.crypto.ASAPKeyStore;

import java.io.IOException;

public class SharkPKIComponentFactory implements SharkComponentFactory {
    private ASAPKeyStore asapKeyStore;
    private SharkPKIComponentImpl instance = null;

    public SharkPKIComponentFactory(ASAPKeyStore asapKeyStore)
    {
        this.asapKeyStore = asapKeyStore;
    }

    @Override
    public SharkComponent getComponent(SharkPeer sharkPeer) throws SharkException {
        if(this.instance == null) {
            try {
                this.instance = new SharkPKIComponentImpl(sharkPeer);
            } catch (IOException e) {
                throw new SharkException(e);
            }
        }
        return this.instance;
    }
}
