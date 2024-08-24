package net.sharksystem.testhelper;

import net.sharksystem.SharkComponent;
import net.sharksystem.SharkException;
import net.sharksystem.SharkPeer;
import net.sharksystem.SharkTestPeerFS;
import net.sharksystem.asap.crypto.ASAPKeyStore;
import net.sharksystem.asap.crypto.InMemoASAPKeyStore;
import net.sharksystem.pki.SharkPKIComponent;
import net.sharksystem.pki.SharkPKIComponentFactory;

public class SharkPKITesthelper extends SharkPeerTestHelper {
    private static final String PKI_COMPONENT_NAME = "sharkPKI";

    public static SharkTestPeerFS setupSharkPeerDoNotStart(CharSequence sharkPeerName, CharSequence testFolder) {
        return new SharkTestPeerFS(sharkPeerName, testFolder + "/" + sharkPeerName);
    }

    public static String getPKITestFolder(CharSequence rootFolder) {
        String folderName = rootFolder + "/" + ASAPTesthelper.getUniqueFolderName(PKI_COMPONENT_NAME);
        System.out.println("TEST RUNS IN FOLDER " + folderName);
        return folderName;
    }

    public static SharkPKIComponent setupPKIComponentPeerNotStarted(SharkPeer sharkPeer, String asapPeerID)
            throws SharkException {


        /*
        InMemoASAPKeyStore keyStore = new InMemoASAPKeyStore(this.peerID);
        keyStore.setMementoTarget(this.appSettings, KEYSTORE_MEMENTO_KEY);
        try {
            keyStore.restoreFromMemento(this.appSettings.getExtra(KEYSTORE_MEMENTO_KEY));
            this.tellUI("restored keystore from memento");
        }
        catch(SharkException se) {
            // no memento for key store - must be new
            this.tellUI("no keystore memento - must be new");
        }
         */

        // this store has no memory
        ASAPKeyStore asapKeyStore = new InMemoASAPKeyStore(asapPeerID);
        // create a component factory
        SharkPKIComponentFactory pkiComponentFactory = new SharkPKIComponentFactory();

        // register this component with shark peer - note: we use interface SharkPeer
        sharkPeer.addComponent(pkiComponentFactory, SharkPKIComponent.class);

        // get component instance
        SharkComponent component = sharkPeer.getComponent(SharkPKIComponent.class);

        // project "clean code" :) we only use interfaces - unfortunately casting is unavoidable
        SharkPKIComponent sharkPKIComponent = (SharkPKIComponent) component;

        return sharkPKIComponent;
    }
}
