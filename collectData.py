import frida
import pandas as pd
import time

# Read and Parse the CSV File
def read_csv(file_path):
    df = pd.read_csv(file_path, header=None, names=['label', 'type'])
    df['label'] = df['label'].str.split('.').str[-1]
    return df['label'].tolist(), df

# Message Handler to Receive Results from Frida Script
def on_message(message, data, results):
    print("HERE")
    if message['type'] == 'send':
        #print("ONMSG")

        print("[*] {0}".format(message['payload']))
        #if 'payload' in message and isinstance(message['payload'], list):
        for i, val in enumerate(message['payload']['payload']):
            #print("--------------------PAYLOAD-------------------------")
            #print(message['payload']['payload'])
            if val == "1" or val == 1:
                results[i] = 1  # Perform OR operation on the result bits
                print(f"Updated results[{i}] to {results[i]}")
    elif message['type'] == 'error':
        print("[!] Error: {0}".format(message['stack']))

# Call the Frida Script
def call_frida_script(device, pid, script_path, input_labels):
    session = device.attach(pid)
    with open(script_path, 'r') as f:
        script_code = f.read()

    script = session.create_script(script_code)
    results = [0] * len(input_labels)
    script.on('message', lambda message, data: on_message(message, data, results))
    script.load()

    # Send input labels to the script
    script.post({'type': 'inputLabels', 'payload': input_labels})

    # Resume the application
    device.resume(pid)

    # Wait for the script to complete processing
    input("wait for script, press enter")  # Ensure the application is fully terminated
  # Adjust this sleep duration as needed

    # Ensure the app is closed properly before spawning again
    device.kill(pid)
    session.detach()
    return results

# Main Function
def main(file_path, frida_script_paths):
    input_labels, df = read_csv(file_path)

    # Connect to the device
    device = frida.get_usb_device()

    # Run the first script
    print("Running the first script...")
    pid = device.spawn(["com.zhiliaoapp.musically"])

    first_results = call_frida_script(device, pid, frida_script_paths[0], input_labels)
    print("First script completed. Results:", first_results)



    # Run the second script
    print("Running the second script...")
    pid2 = device.spawn(["com.zhiliaoapp.musically"])
    second_results = call_frida_script(device, pid2, frida_script_paths[1], input_labels)
    print("Second script completed. Results:", second_results)

    # Ensure the app is closed properly after the second run
    #device.kill(pid2)

    # Combine results with OR operation
    final_results = [a | b for a, b in zip(first_results, second_results)]
    print("Final combined results:", final_results)

# Example Usage
if __name__ == "__main__":
    file_path = "malgenome.csv"
    frida_script_paths = ["permissions_intents.js", "apicalls.js"]

    main(file_path, frida_script_paths)
