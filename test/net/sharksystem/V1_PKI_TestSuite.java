package net.sharksystem;
import net.sharksystem.asap.persons.ASAPCertificateStoreTests;
import net.sharksystem.asap.persons.ExchangeTest;
import net.sharksystem.pki.IntegrationsTestsFromFacade;
import net.sharksystem.pki.SharkComponentUsageTests;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        ExchangeTest.class,
        ASAPCertificateStoreTests.class,
        SharkComponentUsageTests.class,
        IntegrationsTestsFromFacade.class
})
public class V1_PKI_TestSuite {

}
