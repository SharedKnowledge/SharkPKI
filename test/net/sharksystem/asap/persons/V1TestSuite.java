package net.sharksystem.asap.persons;
import net.sharksystem.SharkComponentUsageTests;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        ExchangeTest.class,
        InMemoHelperTests.class,
        ASAPCertificateStoreTests.class,
        SharkComponentUsageTests.class
})
public class V1TestSuite {

}
