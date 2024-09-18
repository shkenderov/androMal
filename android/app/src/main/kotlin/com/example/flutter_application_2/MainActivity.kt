package com.example.malgenome_scriptcall

import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.MethodChannel
import java.io.*

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.example.root_shell/commands"
    private var outputStream: DataOutputStream? = null
    private var inputStream: BufferedReader? = null
    private var errorStream: BufferedReader? = null
    private var process: Process? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        flutterEngine?.dartExecutor?.binaryMessenger?.let { messenger ->
            MethodChannel(messenger, CHANNEL).setMethodCallHandler { call, result ->
                when (call.method) {
                    "runFridaServer" -> {
                        runFridaServer(result)
                    }
                    else -> {
                        result.notImplemented()
                    }
                }
            }
        }

        // Execute the shell command automatically
        //executeShellCommand()
    }

    private fun runFridaServer(result: MethodChannel.Result) {
        Thread {
            try {
                process = Runtime.getRuntime().exec("su")
                outputStream = DataOutputStream(process?.outputStream)
                inputStream = BufferedReader(InputStreamReader(process?.inputStream))
                errorStream = BufferedReader(InputStreamReader(process?.errorStream))

                // Send the sequence of commands
                outputStream?.writeBytes("cd /data/local/tmp\n")
                outputStream?.flush()
                outputStream?.writeBytes("./frida-server\n")
                outputStream?.flush()

                // Read the output of the command
                val output = StringBuilder()
                val errorOutput = StringBuilder()
                var line: String?

                // Reading the standard output
                while (inputStream?.readLine().also { line = it } != null) {
                    output.append(line).append("\n")
                }

                // Reading the error output
                while (errorStream?.readLine().also { line = it } != null) {
                    errorOutput.append(line).append("\n")
                }

                // Debugging logs to help with troubleshooting
                println("Output: ${output.toString()}")
                println("Error: ${errorOutput.toString()}")

                // Return the output or error
                if (errorOutput.isNotEmpty()) {
                    result.success("Error: ${errorOutput.toString()}")
                } else {
                    result.success(output.toString())
                }
            } catch (e: IOException) {
                result.error("EXCEPTION", e.message, null)
            } finally {
                // Cleanup
                try {
                    outputStream?.writeBytes("exit\n")
                    outputStream?.flush()
                    process?.waitFor()
                } catch (e: IOException) {
                    e.printStackTrace()
                }
            }
        }.start()
    }

    private fun executeShellCommand() {
        flutterEngine?.dartExecutor?.binaryMessenger?.let { messenger ->
            MethodChannel(messenger, CHANNEL).invokeMethod("runFridaServer", null)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            outputStream?.writeBytes("exit\n")
            outputStream?.flush()
            process?.waitFor()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }
}
