using Jrss.ExternalAccess;

namespace Jrss.ClassDumper;

public static class ExternalClassDumper
{
    public static (bool ok, string message) Dump(int pid, string outputDir)
    {
        try
        {
            using var ctx = new JvmContext(pid);
            if (!ctx.Initialize())
                return (false, "Failed to initialize JVM context. Make sure the process is a Java/javaw process.");

            var classes = ctx.EnumerateAllClassNames();
            if (classes.Count == 0)
                return (false, "No classes found. The JVM may not have loaded any classes yet.");

            Directory.CreateDirectory(outputDir);
            var path = Path.Combine(outputDir, "_dump_summary.txt");
            File.WriteAllLines(path, classes);
            return (true, $"Dumped {classes.Count} classes to {outputDir}");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
