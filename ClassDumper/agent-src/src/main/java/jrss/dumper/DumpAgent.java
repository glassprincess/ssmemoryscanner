package jrss.dumper;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Агент внешнего дампера классов ("external dumper").
 *
 * Подключается НЕ изнутри процесса (в отличие от LainClassDumper — того, что
 * работает как -javaagent, встроенный в запуск JVM), а СНАРУЖИ: через штатный,
 * официально документированный Java Attach API (com.sun.tools.attach), уже
 * подключаясь к УЖЕ РАБОТАЮЩЕЙ javaw.exe после того, как игра запущена.
 * Это тот же самый механизм, на котором работают VisualVM, async-profiler,
 * jcmd и любые Java-профилировщики — не эксплойт и не инжект в привычном
 * смысле, а штатная возможность JVM разрешать динамическое подключение
 * инструментария (включена по умолчанию, если явно не отключена флагом
 * -XX:+DisableAttachMechanism).
 *
 * Использование агента:
 *   java -jar external-dumper-agent.jar <pid> <outputDir>
 *
 * Это НЕ premain-агент (не грузится при старте JVM) — это отдельный процесс,
 * который сам подключается к целевому PID через VirtualMachine.attach(pid) и
 * подгружает СЕБЯ ЖЕ как java-агент через loadAgent(), после чего agentmain()
 * ниже реально исполняется уже ВНУТРИ целевой JVM.
 */
public final class DumpAgent {

    private static final AtomicInteger DUMPED = new AtomicInteger(0);

    /** Точка входа, когда jar подключается через VirtualMachine.loadAgent(jarPath, args). */
    public static void agentmain(String args, Instrumentation inst) {
        String outputDir = (args == null || args.isBlank()) ? "class-dump" : args;
        run(outputDir, inst);
    }

    /** На случай если кто-то решит подключить агент как обычный -javaagent при старте. */
    public static void premain(String args, Instrumentation inst) {
        agentmain(args, inst);
    }

    private static void run(String outputDir, Instrumentation inst) {
        try {
            Files.createDirectories(Paths.get(outputDir));
        } catch (Exception e) {
            System.err.println("Не удалось создать папку вывода: " + e.getMessage());
            return;
        }

        // 1. Дампим байткод уже загруженных классов через ClassFileTransformer +
        //    retransformClasses — единственный официальный способ получить точный
        //    исходный байткод класса, который был реально загружен JVM.
        ClassFileTransformer dumper = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                     ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                if (className != null) {
                    saveClass(outputDir, className, classfileBuffer);
                }
                return null; // не модифицируем класс, только наблюдаем
            }
        };

        inst.addTransformer(dumper, true);

        Class<?>[] loaded = inst.getAllLoadedClasses();
        int retransformed = 0;
        for (Class<?> c : loaded) {
            try {
                if (inst.isModifiableClass(c) && !c.isArray() && !c.isPrimitive()) {
                    inst.retransformClasses(c);
                    retransformed++;
                }
            } catch (Throwable t) {
                // отдельные классы (особенно core JDK / native) могут отказаться
                // ретрансформироваться — пропускаем и идём дальше, не роняя весь дамп
            }
        }

        inst.removeTransformer(dumper);

        try {
            Files.writeString(
                Paths.get(outputDir, "_dump_summary.txt"),
                "Всего загруженных классов: " + loaded.length + "\n" +
                "Успешно ретрансформировано: " + retransformed + "\n" +
                "Сохранено .class файлов: " + DUMPED.get() + "\n"
            );
        } catch (Exception ignored) {
        }

        System.out.println("[jrss-dumper] готово: " + DUMPED.get() + " классов сохранено в " + outputDir);
    }

    private static void saveClass(String outputDir, String className, byte[] bytes) {
        if (bytes == null) return;
        try {
            // className приходит в виде "java/lang/String" — сохраняем зеркальной структурой папок
            String safe = className.replace('.', '/');
            File file = new File(outputDir, safe + ".class");
            File parent = file.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(bytes);
            }
            DUMPED.incrementAndGet();
        } catch (Exception ignored) {
            // отдельные "странные" имена классов (лямбды, прокси и т.п.) может не
            // получиться сохранить как обычный файл — это ожидаемо, пропускаем
        }
    }
}
