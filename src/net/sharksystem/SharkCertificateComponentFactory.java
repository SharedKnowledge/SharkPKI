package net.sharksystem;

public class SharkCertificateComponentFactory implements SharkComponentFactory {
    private SharkCertificateComponent instance = null;

    @Override
    public SharkComponent getComponent() {
        if(this.instance == null) {
            this.instance = new SharkCertificateComponent();
        }

        return this.instance;
    }
}
