Java.perform(function() {
    setTimeout(function() {

        // Load the ActivityThread class to get the current application context
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        var context = app.getApplicationContext();

        // Get the package manager and the package name
        var PackageManager = Java.use("android.content.pm.PackageManager");
        var packageName = context.getPackageName();
        
        // Get the package info, which includes the permissions
        var packageInfo = context.getPackageManager().getPackageInfo(packageName, PackageManager.GET_PERMISSIONS.value);
        
        // Extract the permissions
        var permissions = packageInfo.requestedPermissions.value;
        //var targetPermissions = global.param.split(',');  // Parse the array of permissions passed as a parameter
        
        //console.log("Package: " + packageName);
        //var foundPermissions = [];
        if (permissions) {
            //console.log("Permissions:");
            for (var i = 0; i < permissions.length; i++) {
                //if (targetPermissions.indexOf(permissions[i]) !== -1) {
                    console.log(permissions[i]);
                    //foundPermissions.push(permissions[i]);
                //}
            }
        } else {
            //console.log("No permissions found.");
        }

        // Print the results in a format that can be parsed by the Python script
        //console.log("Found:" + foundPermissions.join(','));

        // Exit the Frida script
        Java.perform(function() {
            var System = Java.use('java.lang.System');
            System.exit(0);
        });
        
    }, 5000);
});
