package net.sharksystem.pki;

import net.sharksystem.SharkComponent;
import net.sharksystem.SharkException;
import net.sharksystem.SharkPeer;
import net.sharksystem.SharkTestPeerFS;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;

import static net.sharksystem.pki.TestConstants.*;
import static net.sharksystem.pki.TestConstants.CLARA_NAME;

public class TestHelper {
    public static final String SPECIFIC_ROOT_FOLDER = ROOT_DIRECTORY + "sharkComponentTests/";
    public static final String ALICE_FOLDER = SPECIFIC_ROOT_FOLDER + ALICE_NAME;
    public static final String BOB_FOLDER = SPECIFIC_ROOT_FOLDER + BOB_NAME;
    public static final String CLARA_FOLDER = SPECIFIC_ROOT_FOLDER + CLARA_NAME;
    public static final byte[] LOST_BYTES = new byte[] {4, 8, 15, 16, 23, 42};

    private static int portnumber = 7000;

    public static int getPortNumber() {
        portnumber++;
        return portnumber;
    }

    public static SharkPKIComponent setupComponent(CharSequence peerID, SharkPeer sharkPeer) throws SharkException {
        // create a component factory
        SharkPKIComponentFactory certificateComponentFactory = new SharkPKIComponentFactory();

        // register this component with shark peer - note: we use interface SharkPeer
        sharkPeer.addComponent(certificateComponentFactory, SharkPKIComponent.class);

        // get component instance
        SharkComponent component = sharkPeer.getComponent(SharkPKIComponent.class);

        // project "clean code" :) we only use interfaces - unfortunately casting is unavoidable
        SharkPKIComponent sharkPKIComponent = (SharkPKIComponent) component;

        return sharkPKIComponent;
    }
}
