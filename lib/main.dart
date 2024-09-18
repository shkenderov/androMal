import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:tflite_flutter/tflite_flutter.dart';
import 'dart:io';
import 'package:csv/csv.dart';
import 'package:file_picker/file_picker.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:open_file_plus/open_file_plus.dart';
void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: Text('TFLite Example with Shell Command'),
        ),
        body: TFLiteDemo(),
      ),
    );
  }
}

class TFLiteDemo extends StatefulWidget {
  @override
  _TFLiteDemoState createState() => _TFLiteDemoState();
}

class _TFLiteDemoState extends State<TFLiteDemo> {
  static const platform = MethodChannel('com.example.root_shell/commands');

  String _output = "Loading model...";
  late Interpreter _interpreter;
  late List<String> _labels;

  @override
  void initState() {
    super.initState();
    //runFridaServer();
    //loadModel();
  }
  Future<void> _runFridaServer() async {
    String result;
    try {
      result = await platform.invokeMethod('runFridaServer');
      setState(() {
        _output = result;
      });
    } on PlatformException catch (e) {
      setState(() {
        _output = "Failed to run frida-server: '${e.message}'.";
      });
    }
  }
Future<List<List<double?>>> readCsvFile() async {
  // Request storage permission
  if (await Permission.storage.request().isGranted) {
    try {
      // Use File Picker to pick the CSV file
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['csv'],
      );

      if (result != null) {
        String? filePath = result.files.single.path;

        if (filePath != null) {
          // Read the file
          final file = File(filePath);
          final csvContent = await file.readAsString();

          // Parse the CSV content
          List<List<dynamic>> csvTable = const CsvToListConverter().convert(csvContent);

          // Convert the parsed CSV to a List<List<int>>, skipping non-integer values
          List<List<double?>> results = csvTable.map((row) {
            return row.map((cell) {
              try {
                return double.parse(cell.toString());
              } catch (e) {
                print('Skipping non-integer value: $cell');
                return null; // or you could return a default value like 0
              }
            }).where((value) => value != null).toList();
          }).toList();

          print(results);
          return results;
        } else {
          print('File path is null.');
          return [];
        }
      } else {
        print('No file selected.');
        return [];
      }
    } catch (e) {
      print('Error reading file: $e');
      return [];
    }
  } else {
    print('Storage permission denied.');
    return [];
  }
}


  Future<void> runFridaServer() async {
    try {
      final result = await platform.invokeMethod('runFridaServer');
      print('Frida Server Output: $result');
    } on PlatformException catch (e) {
      print("Failed to run frida-server: '${e.message}'.");
    }
  }

  Future<void> loadModel() async {
    try {
      // Load the TFLite model
      _interpreter = await Interpreter.fromAsset('assets/malgenome_float16.tflite');
      
      // Load labels
      String labelsData = await rootBundle.loadString('assets/malgenome_labels_out.txt');
      _labels = labelsData.split('\n');

      print("Model and labels loaded successfully");
      //evaluateModel();
       setState(() {
        _output = "Model and labels loaded successfully";
      });
    } catch (e) {
      print("Failed to load model: $e");
      setState(() {
        _output = "Failed to load model";
      });
    }
  }

  List<double> softmax(List<double> logits) {
    final expScores = logits.map((logit) => exp(logit)).toList();
    final sumExpScores = expScores.reduce((a, b) => a + b);
    return expScores.map((score) => score / sumExpScores).toList();
  }

  void evaluateModel() async {
    int timestampBegin = DateTime.now().millisecondsSinceEpoch;
    try {
      // Generate random input data with 215 columns to match the expected input size
      //List<double> inputData = List.generate(215, (index) => Random().nextInt(2).toDouble()); //RAND
      //List<double> inputData = List.generate(215, (index) => 0.0); //ONLY 0s

      //Read CSV data
      List<List<double?>> csvData = await readCsvFile();

      // Flatten and convert the CSV data to a List<double>, filtering out nulls
      List<double> inputData = csvData
          .expand((row) => row)
          .where((value) => value != null) // Filter out nulls
          .map((value) => value!.toDouble()) // Safely unwrap non-null values
          .toList();

      // Check if the inputData has the required 215 elements
      if (inputData.length > 216) {
        throw Exception("CSV data does not have exactly 215 elements. Found: ${inputData.length}");
      }
      else if(inputData.length == 216){
        print("Index is one more than needed. This is a known bug and will be handled.");
        inputData.removeAt(0);
      }

      // Prepare input tensor
      var input = Float32List.fromList(inputData);

      // Prepare output tensor (assuming the model has 2 outputs for binary classification)
      var output = List.filled(2, 0.0).reshape([1, 2]);

      // Run inference
      _interpreter.run(input, output);

      // Print raw outputs for debugging
      print("Raw output: $output");

      // Apply softmax to the raw output logits to get probabilities
      List<double> probabilities = softmax(output[0]);

      // Retrieve the results
      double maxConfidence = -1;
      int maxIndex = -1;

      for (int i = 0; i < probabilities.length; i++) {
        if (probabilities[i] > maxConfidence) {
          maxConfidence = probabilities[i];
          maxIndex = i;
        }
      }

      String predictedLabel = _labels[maxIndex];
      double confidence = probabilities[maxIndex];
      int time = DateTime.now().millisecondsSinceEpoch - timestampBegin;

      setState(() {
        _output = "Predicted: $predictedLabel (Confidence: $confidence, Time: $time)";
      });
    } catch (e) {
      // Catch any errors and display them
      setState(() {
        _output = "Error running model: $e";
        print(e);
      });
    }
  }

 @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        children: [
          ElevatedButton(
            onPressed: _runFridaServer,
            child: Text('Run Frida Server'),
          ),
          SizedBox(height: 16),
          ElevatedButton(
            onPressed: loadModel,
            child: Text('Load Model'),
          ),
          SizedBox(height: 16),
          ElevatedButton(
            onPressed: evaluateModel,
            child: Text('Evaluate Model'),
          ),
          SizedBox(height: 16),
          ElevatedButton(
            onPressed: readCsvFile,
            child: Text('Read Script results'),//
          ),
          SizedBox(height: 16),
          Text('Output:'),
          SizedBox(height: 8),
          Text(_output!),
        ],
      ),
    );
  }
}