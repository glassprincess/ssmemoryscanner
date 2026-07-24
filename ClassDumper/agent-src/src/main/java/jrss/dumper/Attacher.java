package jrss.dumper;

import com.sun.tools.attach.VirtualMachine;

/**
 * Точка входа jar-файла: подключается к целевому PID через штатный Attach API
 * и просит целевую JVM подгрузить этот же jar как java-агент (agentmain).
 *
 * Использование:
 *   java -jar external-dumper-agent.jar <pid> <outputDir>
 *
 * Требования: у процесса-оператора должен быть доступ к целевому PID (тот же
 * пользователь Windows, либо права администратора) — Attach API не даёт
 * никакого доступа, которого у оператора уже не было бы через диспетчер
 * задач/отладчик. Если целевая JVM запущена с -XX:+DisableAttachMechanism,
 * подключение не сработает — это ожидаемое и штатное поведение JVM.
 */
public final class Attacher {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Использование: java -jar external-dumper-agent.jar <pid> <outputDir>");
            System.exit(2);
            return;
        }

        String pid = args[0];
        String outputDir = args[1];

        String jarPath = new java.io.File(
            Attacher.class.getProtectionDomain().getCodeSource().getLocation().toURI()
        ).getAbsolutePath();

        VirtualMachine vm = null;
        try {
            vm = VirtualMachine.attach(pid);
            vm.loadAgent(jarPath, outputDir);
            System.out.println("[jrss-dumper] агент подключён к PID " + pid + ", вывод: " + outputDir);
        } catch (Exception e) {
            System.err.println("[jrss-dumper] не удалось подключиться к PID " + pid + ": " + e.getMessage());
            System.exit(1);
        } finally {
            if (vm != null) {
                try {
                    vm.detach();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
