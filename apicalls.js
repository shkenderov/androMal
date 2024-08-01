Java.perform(function() {
    var inputLabels = [];
    var results = [];

    // Function to initialize inputLabels from Python
    function initializeInputLabels() {
        //console.log("here");
        recv('inputLabels', function(message) {
            inputLabels = message.payload;
            results = new Array(inputLabels.length).fill(0);
            console.log("Input labels initialized: 2nd script");
        }).wait();
    }
    function communicateResults() {
        console.log("Results after api calls: " + JSON.stringify(results));
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
                    console.log("----------------------METHOD LABEL------------------------");
                    console.log(methodLabel);
                    //await sleepNow(10000)

                    var index = inputLabels.indexOf(methodLabel);
                    console.log(index);
                    console.log("------END-------------METHOD LABEL-----------END----------");

                    if (index !== -1) {
                        results[index] = 1;
                    }
                    //console.log("hookMethod detected: Called " + className + "." + methodName + " with args: " + JSON.stringify(arguments));
                    return method.apply(this, arguments);
                };
            });
        } catch (e) {
            console.log("Error hooking into " + className + "." + methodName + ": " + e);
        }
    }
    const sleepNow = (delay) => new Promise((resolve) => setTimeout(resolve, delay))
    var flag=0;
    function hookAllMethods(className) {
        //console.log("FLAG outside BEFORE:" + flag);
        if(flag==0){
          
            console.log("FLAG INSIDE BEFORE:" + flag);

            flag=1;
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                console.log("METHODS");
                console.log(methods.length);
                if(!methods.length){
                    console.log("FLAG CHANGE");

                    flag=0;
                }else{
                    setTimeout(communicateResults, 5000); // Adjust the delay as needed
                }
                methods.forEach(function(method) {
                    var methodName = method.getName();
                    //console.log(methodName);
                    hookMethod(className, methodName);
                });
            } catch (e) {
                console.log("Error hooking into all methods of " + className + ": " + e);
            }
            console.log("FLAG INSIDE after:" + flag);
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
