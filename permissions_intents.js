Java.perform(function() {
    var inputLabels = [];
    var results = [];
    function communicateResults() {
        console.log("Results after permissions and intents: " + JSON.stringify(results));
        send({ type: 'results', payload: results });
    }
    // Function to initialize inputLabels from Python
    function initializeInputLabels() {
        recv('inputLabels', function(message) {
            inputLabels = message.payload;
            results = new Array(inputLabels.length).fill(0);
            console.log("Input labels initialized: 1st script" );
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
                console.log("Permission detected: " + permission);
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
                    console.log("INDEX "+index);
                    console.log(results[index]);

                }
                /*if (!printedActions.has(actionLabel)) {
                    //console.log("Intent detected: " + actionLabel);
                    printedActions.add(actionLabel);
                }*/
            }
            return intent;
        };

        console.log("Results after permissions and intents: " + JSON.stringify(results));

        // Communicate the results back to Python
        //send({type: 'results', payload: results});
        setTimeout(communicateResults, 10000); // Adjust the delay as needed
    }, 5000); // Delay for permissions and intents check
});
