package net.sharksystem.persons;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        ExchangeTest.class,
        InMemoHelperTests.class,
        PersonsStorageTests.class
})
public class V1TestSuite {

}
