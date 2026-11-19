package dev.aero.menu

import android.content.Context
import java.io.File
import java.io.FileOutputStream

/**
 * Copies the bundled injector binary and target .so out of assets, stages them in
 * /data/local/tmp (not the app's own private files dir, which the target process's
 * SELinux domain typically cannot read even with 755 Unix permissions), then runs
 * the injector as root against a running process. Unverified beyond what the log
 * from a real run shows: read [InjectResult.log] after calling [inject].
 */
object RootInjector {

    const val VERSION = "0.6"

    private const val STAGING_DIR = "/data/local/tmp/aero"

    data class InjectResult(val success: Boolean, val log: String)

    // Names/paths to try as the su binary, invoked through /system/bin/sh -c rather
    // than as ProcessBuilder's argv[0] directly: ProcessBuilder resolves a bare
    // command name by searching PATH itself, in user space, and throws before ever
    // calling execve if it doesn't find a real file there. Root frameworks that hook
    // execve (KernelSU included) only get a chance to act once execve is actually
    // called, so routing through a shell's own exec resolution is what lets that
    // hook fire.
    private val SU_CANDIDATES = listOf(
        "su",
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/debug_ramdisk/su",
    )

    private fun copyAsset(context: Context, assetName: String, outFile: File) {
        context.assets.open(assetName).use { input ->
            FileOutputStream(outFile).use { output -> input.copyTo(output) }
        }
    }

    private fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    /** Runs `command` as `<suBinary> -c <command>`, itself invoked via `sh -c` so that
     * su's own name resolution happens inside the shell, not inside ProcessBuilder. */
    private fun runWith(suBinary: String, command: String): Pair<Int, String> {
        val inner = "$suBinary -c ${shellQuote(command)}"
        val process = ProcessBuilder("/system/bin/sh", "-c", inner)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exit = process.waitFor()
        return exit to output
    }

    /** Finds a working su binary, trying [SU_CANDIDATES] in order. A candidate only
     * counts as working if `id` actually ran under it with exit code 0. */
    private fun resolveSu(log: StringBuilder): String? {
        for (candidate in SU_CANDIDATES) {
            try {
                val (exit, out) = runWith(candidate, "id")
                log.append("su candidate '$candidate' -> exit=$exit out='${out.trim()}'\n")
                if (exit == 0) return candidate
            } catch (e: Exception) {
                log.append("su candidate '$candidate' -> failed to run (${e.javaClass.simpleName}: ${e.message})\n")
            }
        }
        return null
    }

    /**
     * @param packageName the target game's package, e.g. "com.axlebolt.standoff2"
     */
    fun inject(context: Context, packageName: String): InjectResult {
        val log = StringBuilder()
        log.append("Aero injector v$VERSION\n")
        try {
            val suBinary = resolveSu(log)
            if (suBinary == null) {
                log.append("No working su binary found among: ${SU_CANDIDATES.joinToString()}\n")
                return InjectResult(false, log.toString())
            }
            log.append("Using su candidate: $suBinary\n")

            // Stage in the app's own files dir first (writable without root), then
            // move the copies into /data/local/tmp as root so the target process's
            // SELinux domain can actually open them: files under this app's own
            // app_data_file context are normally invisible to other apps even when
            // the Unix mode bits say 755.
            val localInjector = File(context.filesDir, "injector")
            val localLib = File(context.filesDir, "liblemmingrmt.so")
            copyAsset(context, "injector", localInjector)
            copyAsset(context, "liblemmingrmt.so", localLib)

            val stagedInjector = "$STAGING_DIR/injector"
            val stagedLib = "$STAGING_DIR/liblemmingrmt.so"
            val stageCmd = "mkdir -p $STAGING_DIR && " +
                    "cp ${localInjector.absolutePath} $stagedInjector && " +
                    "cp ${localLib.absolutePath} $stagedLib && " +
                    "chmod 755 $STAGING_DIR $stagedInjector $stagedLib"
            val (stageExit, stageOut) = runWith(suBinary, stageCmd)
            log.append("stage to $STAGING_DIR -> exit=$stageExit out='$stageOut'\n")
            if (stageExit != 0) {
                return InjectResult(false, log.toString())
            }

            // Best-effort SELinux relabel; some policies need this even after a
            // correct chmod, others ignore it. Failure here is not fatal on its own.
            val (chconExit, chconOut) = runWith(suBinary, "chcon u:object_r:system_file:s0 $stagedLib")
            log.append("chcon (best-effort) -> exit=$chconExit out='${chconOut.trim()}'\n")

            val (lsExit, lsOut) = runWith(suBinary, "ls -Z $stagedLib")
            log.append("ls -Z -> exit=$lsExit out='${lsOut.trim()}'\n")

            val (pidExit, pidOut) = runWith(suBinary, "pidof $packageName")
            val pid = pidOut.trim().split(Regex("\\s+")).firstOrNull()?.toIntOrNull()
            log.append("pidof $packageName -> exit=$pidExit out='${pidOut.trim()}'\n")
            if (pid == null) {
                log.append("Could not find a running process for $packageName. Start the game first.\n")
                return InjectResult(false, log.toString())
            }

            val (ctxExit, ctxOut) = runWith(suBinary, "cat /proc/$pid/attr/current")
            log.append("target SELinux context -> exit=$ctxExit out='${ctxOut.trim()}'\n")

            val injectCmd = "$stagedInjector $pid $stagedLib"
            val (injectExit, injectOut) = runWith(suBinary, injectCmd)
            log.append("inject -> exit=$injectExit\n$injectOut\n")
            return InjectResult(injectExit == 0, log.toString())
        } catch (e: Exception) {
            log.append("Exception: ${e.javaClass.simpleName}: ${e.message}\n")
            return InjectResult(false, log.toString())
        }
    }
}
