package net.sharksystem.asap.persons;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        ExchangeTest.class,
        InMemoHelperTests.class,
        ASAPCertificateStoreTests.class
})
public class V1TestSuite {

}
