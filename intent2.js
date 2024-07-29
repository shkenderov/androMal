Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    var printedActions = new Set(); // Set to track printed actions

    Activity.getIntent.overload().implementation = function () {
        var intent = this.getIntent();
        var action = intent.getAction();

        if (action && !printedActions.has(action)) {
            console.log(action);
            printedActions.add(action);
        }

        return intent;
    };
    // Schedule script termination after 30 seconds
    setTimeout(function() {
        //console.log("Detaching script after 30 seconds.");
        var System = Java.use('java.lang.System');
        System.exit(0); // Detach the script
    }, 10000); // 30 seconds in milliseconds
});
