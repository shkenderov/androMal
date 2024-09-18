Java.perform(function() {
    var inputLabels = [];
    var results = [];
    var BufferedReader = Java.use("java.io.BufferedReader");
    var FileReader = Java.use("java.io.FileReader");
    var pid = Process.id;

    function getCpuUsage() {
        var statPath = "/proc/" + pid + "/stat";
        try {
            var reader = BufferedReader.$new(FileReader.$new(statPath));
            var line = reader.readLine();
            reader.close();
            if (line) {
                var stats = line.split(" ");
                console.log("CPU Usage Data: utime=" + stats[13] + ", stime=" + stats[14]);
            }
        } catch (e) {
            console.log("Error reading " + statPath + ": " + e.message);
        }
    }

    function getRamUsage() {
        var statusPath = "/proc/" + pid + "/status";
        try {
            var reader = BufferedReader.$new(FileReader.$new(statusPath));
            var line;
            while ((line = reader.readLine()) !== null) {
                if (line.indexOf("VmRSS:") !== -1) {
                    console.log("RAM Usage (VmRSS): " + line.trim());
                    break;
                }
            }
            reader.close();
        } catch (e) {
            console.log("Error reading " + statusPath + ": " + e.message);
        }
    }

    function communicateResults() {
        getCpuUsage();
        getRamUsage();
        console.log("Sending permissions & intents to python script... \n");

        send({ type: 'results', payload: results });
    }
    // Function to initialize inputLabels from Python
    function initializeInputLabels() {
        recv('inputLabels', function(message) {
            inputLabels = message.payload;
            results = new Array(inputLabels.length).fill(0);
            console.log("Input labels initialized for Frida script: Permissions & Intents \n" );
        }).wait();
    }

    // Call initializeInputLabels to populate inputLabels
    initializeInputLabels();

    setTimeout(function() {
        // Check permissions
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        var context = app.getApplicationContext();
        var PackageManager = Java.use("android.content.pm.PackageManager");
        var packageName = context.getPackageName();
        var packageInfo = context.getPackageManager().getPackageInfo(packageName, PackageManager.GET_PERMISSIONS.value);
        var permissions = packageInfo.requestedPermissions.value;

        if (permissions) {
            for (var i = 0; i < permissions.length; i++) {
                var permission = permissions[i].split('.').pop(); // Extract the last part
                var index = inputLabels.indexOf(permission);
                if (index !== -1) {
                    results[index] = 1;
                }
                console.log("Detected: " + permission);
            }
        }


        // Check intents
        var Activity = Java.use("android.app.Activity");
        var printedActions = new Set();

        Activity.getIntent.overload().implementation = function () {
            var intent = this.getIntent();
            var action = intent.getAction();
            if (action) {
                var actionLabel = action.split('.').pop(); // Extract the last part
                var index = inputLabels.indexOf(actionLabel);
                if (index !== -1) {
                    results[index] = 1;
                }
                console.log("Detected intent: "+actionLabel);

                /*if (!printedActions.has(actionLabel)) {
                    //console.log("Intent detected: " + actionLabel);
                    printedActions.add(actionLabel);
                }*/
            }
            
            return intent;
        };
        //CHECK Commands
        // Hook into execve function
        Interceptor.attach(Module.findExportByName(null, 'execve'), {
            onEnter: function(args) {
                var command = Memory.readCString(args[0]);
                var index = inputLabels.indexOf(command);
                if (index !== -1) {
                    results[index] = 1;
                }
                console.log("Detected execve command: "+command);                
            },
        });

        // Hook into system function
        Interceptor.attach(Module.findExportByName(null, 'system'), {
            onEnter: function(args) {
                var command = Memory.readCString(args[0]);
                var index = inputLabels.indexOf(command);
                if (index !== -1) {
                    results[index] = 1;
                }
                console.log("Detected system command: "+command);       
            },
        });

        // Hook into popen function (common for creating pipes to execute commands)
        Interceptor.attach(Module.findExportByName(null, 'popen'), {
            onEnter: function(args) {
                var command = Memory.readCString(args[0]);
                var index = inputLabels.indexOf(command);
                if (index !== -1) {
                    results[index] = 1;
                }
                console.log("Detected popen command: "+command);       
            },
        });


        //console.log("Results after permissions and intents: " + JSON.stringify(results));

        // Communicate the results back to Python
        //send({type: 'results', payload: results});
       
        setTimeout(communicateResults, 10000); // Adjust the delay as needed
    }, 5000); // Delay for permissions and intents check
});
