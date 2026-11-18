// TRR9040 Procedure A: make the HotSpot JVM write its fatal error log
// (hs_err_pid<pid>.log), the on-disk artifact a C2 JIT memory-corruption crash
// such as CVE-2026-114938 ("Java4Shell") leaves behind.
//
// SAFETY: this is NOT an exploit. It holds no Base64 input, calls no intrinsic and
// corrupts no memory. It fills a tiny heap (the caller passes -Xmx16m) until the
// JVM throws OutOfMemoryError, and -XX:+CrashOnOutOfMemoryError (a standard product
// flag) turns that error into a VM fatal error. HotSpot's error handler then writes
// the same hs_err_pid<pid>.log file it writes for a SIGSEGV in compiled code. The
// process ends; nothing else on the host is touched.
public class Trr9040Crash {
    public static void main(String[] args) {
        long[][] keep = new long[1024][];
        for (int i = 0; i < keep.length; i++) {
            keep[i] = new long[1 << 20];  // 8 MiB per row: the 16 MiB heap fills fast
        }
        System.out.println("no OutOfMemoryError: the heap was not limited");
    }
}
