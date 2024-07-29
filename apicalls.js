Java.perform(function() {
    // Function to hook into a specific method of a class
    function hookMethod(className, methodName) {
        try {
            var clazz = Java.use(className);
            var methods = clazz[methodName].overloads;
            methods.forEach(function(method) {
                method.implementation = function() {
                    console.log("Called " + className + "." + methodName + " with args: " + JSON.stringify(arguments));
                    return method.apply(this, arguments);
                };
            });
        } catch (e) {
            // Handle the error gracefully
            console.log("Error hooking into " + className + "." + methodName + ": " + e);
        }
    }

    // Function to hook into all methods of a class
    function hookAllMethods(className) {
        try {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();
            methods.forEach(function(method) {
                var methodName = method.getName();
                hookMethod(className, methodName);
            });
        } catch (e) {
            console.log("Error hooking into all methods of " + className + ": " + e);
        }
    }

    // Iterate over all loaded classes and hook their methods
    var loadedClasses = Java.enumerateLoadedClassesSync();
    loadedClasses.forEach(function(className) {
        hookAllMethods(className);
    });

    console.log("Finished hooking all methods.");
});
