package net.sharksystem;

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
