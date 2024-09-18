Java.perform(function() {
    var inputLabels = [];
    var results = [];
    var pid = Process.id;

    // Import Java classes
    var BufferedReader = Java.use("java.io.BufferedReader");
    var FileReader = Java.use("java.io.FileReader");

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


    // Periodically fetch CPU and RAM usage
    /*setInterval(function() {
        getCpuUsage();
        getRamUsage();
    }, 1000); // Fetch every 1 second
*/
    // Function to initialize inputLabels from Python
    function initializeInputLabels() {
        //console.log("here");
        recv('inputLabels', function(message) {
            inputLabels = message.payload;
            results = new Array(inputLabels.length).fill(0);
            console.log("Input labels initialized: API CALLS script");
        }).wait();
    }
    function communicateResults() {
        getCpuUsage();
        getRamUsage();
        console.log("Sending API CALL results to python script... \n");
        
        send({ type: 'results', payload: results });
    }
    // Call initializeInputLabels to populate inputLabels
    initializeInputLabels();

    // Function to hook methods
    function hookMethod(className, methodName) {
        try {
            var clazz = Java.use(className);
            var methods = clazz[methodName].overloads;
            methods.forEach(function(method) {
                method.implementation = function() {
                    //console.log("here")
                    var methodLabel = methodName.split('.').pop(); // Extract the last part.
                    var index = inputLabels.indexOf(methodLabel);
                    if (index !== -1) {
                        results[index] = 1;
                        console.log("hookMethod detected: Called " + className + "." + methodName);

                    }
                    count++;
                    console.log("COUNT: "+ count);
                    getCpuUsage();
                    getRamUsage();
                    return method.apply(this, arguments);
                };
            });
        } catch (e) {
            console.log("Error hooking into " + className + "." + methodName + ": " + e);
        }
    }
    const sleepNow = (delay) => new Promise((resolve) => setTimeout(resolve, delay))
    var flag=0;
    var count=0;
    function hookAllMethods(className) {
        if(flag==0){
            flag=1;
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                if(!methods.length){
                    flag=0;
                }else{
                    setTimeout(communicateResults, 5000); // Adjust the delay as needed
                }
                methods.forEach(function(method) {
                    var methodName = method.getName();
                    hookMethod(className, methodName);
                });
            } catch (e) {
                console.log("Error hooking into all methods of " + className + ": " + e);
            }
        }
    }

    // Enumerate all loaded classes and hook their methods
    var loadedClasses = Java.enumerateLoadedClassesSync();
    loadedClasses.forEach(function(className) {
        hookAllMethods(className);
    });

    // Communicate the results back to Python
    //send({type: 'results', payload: results});.

});
