import os
import subprocess
import time
import frida
import pandas as pd
import sys

# Function to start the Frida server
def start_frida_server():
    frida_server_path = "./data/local/tmp/frida-server"
    # Ensure frida-server is executable
    subprocess.run(["chmod", "755", frida_server_path])
    
    # Start frida-server in background
    subprocess.Popen([frida_server_path, "&"])
    time.sleep(2)  # Wait for the server to start

# Read and Parse the CSV File
def read_csv_malgenome(): 
    file_path = "malgenome.csv"
    df = pd.read_csv(file_path, header=None, names=['label', 'type'])
    df['label'] = df['label'].str.split('.').str[-1]
       
    return df['label'].tolist(), df

def read_csv_mh100k():
    file_path = "MH100kFeatures.csv"
    df = pd.read_csv(file_path, header=None, names=['index', 'label'])
    #df['label'] = df['label'].str.split('::').str[-1].str.split('.').str[-1].str.replace(r'\(.*\)', '', regex=True)
    df['label'] = df['label'].str.replace(r'^.*::(.*)\.(.*)\(.*\)$|^.*::(.*)\.(.*)$|^.*::(.*)\((.*)\)$|^.*::(.*)\.(.*)', r'\2\4\6\8', regex=True)

    return df['label'].tolist(), df


def read_csv_mh100k_old():
    file_path = "mh_100k_features_all.csv"
    
    # Read the CSV file and skip the first row
    df = pd.read_csv(file_path, header=None, skiprows=1, names=['index', 'label'])
    
    # Remove everything before and including "::" in the 'label' column
    df['label'] = df['label'].str.split('::').str[-1]
    
    # Save the modified DataFrame to a new CSV file
    df.to_csv('resultsmh100k.csv', index=False)
    
    # Print the 'label' column as a list
    print(df['label'].tolist())
    
    # Wait for user input
    input("here")
    
    # Return the 'label' column as a list and the DataFrame
    return df['label'].tolist(), df
# Message Handler to Receive Results from Frida Script
def on_message(message, data, results):
    if message['type'] == 'send':
        #print("[*] {0}".format(message['payload']))
        print("Frida Data received in python script \n")
        for i, val in enumerate(message['payload']['payload']):
            if val == "1" or val == 1:
                results[i] = 1  # Perform OR operation on the result bits
                print(f"Updated results[{i}] to {results[i]}")
    elif message['type'] == 'error':
        print("[!] Error: {0}".format(message['stack']))
    print("Message proccessed. Please press ENTER. \n")

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
    input("wait for the python script to receive data, then press enter \n")  # Ensure the application is fully terminated

    # Ensure the app is closed properly before spawning again
    device.kill(pid)
    session.detach()
    return results

# Main Function
def main(frida_script_paths):
    context= input("Which model do you want to use? 1 for malgenome, 2 for MH100k \n")
    if context=='1':
        input_labels, df = read_csv_malgenome()
    elif context=='2':
        input_labels, df = read_csv_mh100k()
    else:
        print("Bad input")
        sys.exit(1)
    # Connect to the device
    device = frida.get_usb_device()

    # Run the first script
    print("Running the first script...")
    pid = device.spawn(["com.google.android.youtube"])
    #pid = device.spawn(["/system/bin/su", "-c", "com.google.android.youtube"]) 

    first_results = call_frida_script(device, pid, frida_script_paths[0], input_labels)
    print("First script completed. \n")

    # Run the second script
    print("Running the second script...")
    pid2 = device.spawn(["com.google.android.youtube"])
    second_results = call_frida_script(device, pid2, frida_script_paths[1], input_labels)
    print("Second script completed. Results:", second_results)

    # Combine results with OR operation
    final_results = [a | b for a, b in zip(first_results, second_results)]
    print("Final combined results:", final_results)
    dfout = pd.DataFrame(final_results)
    csv_filename = 'results.csv'
    dfout.to_csv(csv_filename, index=False)
    input("Press enter to upload the results to phone")
    local_file_path = 'results.csv'
    if context == '1':

        device_file_path = '/sdcard/resultsMalgenome.csv'  # Commonly accessible path on the device

    elif context == '2':
        device_file_path = '/sdcard/resultsMH100k.csv'  # Commonly accessible path on the device
    # Push the file to the device using adb
    try:
        result = subprocess.run(['adb', 'push', local_file_path, device_file_path], capture_output=True, text=True)
        if result.returncode == 0:
            print(f'Successfully pushed {local_file_path} to {device_file_path}')
        else:
            print(f'Failed to push the file. Error: {result}')
    except FileNotFoundError:
        print("ADB is not installed or not found in PATH.")
# Example Usage
if __name__ == "__main__":
    #start_frida_server()  # Start Frida server
    frida_script_paths = ["permissions_intents.js", "apicalls.js"]
    main(frida_script_paths)
