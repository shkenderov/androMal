import pandas as pd
import subprocess
import re
import json

# Step 1: Read and Parse the CSV File
def read_csv(file_path):
    df = pd.read_csv(file_path, header=None, names=['label', 'type'])
    df['label'] = df['label'].str.split('.').str[-1]
    print(df.head())
    return df

# Step 2: Extract the last part of the label (Currently not used, can be integrated if needed)
def extract_label(label):
    print(re.split(r'[.:]', label)[-1])
    return re.split(r'[.:]', label)[-1]

# Step 3: Call Frida Scripts Sequentially
def call_frida_script(script_path):
    process = subprocess.run(
        ["frida", "-U", "-f", "com.zhiliaoapp.musically", "-l", script_path], 
        text=True, capture_output=True
    )
    return process.stdout.strip()

# Step 4: Collect and Format Results
def collect_results(df, frida_scripts):
    df['extracted_label'] = df['label']  # Extract label if necessary
    #print( df['extracted_label'])
    # Initialize the 'detected' columns with 0 for each label type
    for label_type in frida_scripts.keys():
        df[f'detected'] = 0

    # Iterate over each script and update the 'detected' columns
    for label_type, script_path in frida_scripts.items():
        script_output = call_frida_script(script_path)
        print("FRIDA OUTPUT")
      
        detected_items = set(map(lambda s: s.strip().split(".")[-1] if "." in s else s.strip(),
                                 script_output.split("->")[-1].split("Process terminated")[0].splitlines()))
        print(detected_items)
        df[f'detected'] = df['extracted_label'].apply(lambda x: 1 if x in detected_items else 0)

    return df

# Main Function
def main(file_path, frida_scripts):
    df = read_csv(file_path)
    results = collect_results(df, frida_scripts)
    return results

# Example Usage
if __name__ == "__main__":
    file_path = "malgenome.csv"
    frida_scripts = {
        #"Manifest Permission": "permissionsL.js",
        # "API call signature": "path/to/your/api_calls_script.js",
        "Intent": "intent2.js"
    }

    results = main(file_path, frida_scripts)
    results.to_csv('res.csv', index=False)
