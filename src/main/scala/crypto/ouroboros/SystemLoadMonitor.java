package crypto.ouroboros;

import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

public class SystemLoadMonitor {
    OperatingSystemMXBean bean = (com.sun.management.OperatingSystemMXBean) ManagementFactory
            .getOperatingSystemMXBean();
    public static void main(String[] args) {}
    double cpuLoad() {
        double value = bean.getSystemCpuLoad();
        return value;
    }
}
