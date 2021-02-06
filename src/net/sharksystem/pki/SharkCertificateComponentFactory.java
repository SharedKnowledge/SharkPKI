package net.sharksystem.pki;

import net.sharksystem.SharkComponent;
import net.sharksystem.SharkComponentFactory;

public class SharkCertificateComponentFactory implements SharkComponentFactory {
    private SharkCertificateComponentImpl instance = null;

    @Override
    public SharkComponent getComponent() {
        if(this.instance == null) {
            this.instance = new SharkCertificateComponentImpl();
        }

        return this.instance;
    }
}
