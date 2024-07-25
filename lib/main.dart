import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:tflite_flutter/tflite_flutter.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: Text('TFLite Example'),
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
  String? _output = "Loading model...";
  late Interpreter _interpreter;
  late List<String> _labels;

  @override
  void initState() {
    super.initState();
    loadModel();
  }

  Future<void> loadModel() async {
    try {
      // Load the TFLite model
      _interpreter = await Interpreter.fromAsset('assets/malgenome_float16.tflite');
      
      // Load labels
      String labelsData = await rootBundle.loadString('assets/malgenome_labels_out.txt');
      _labels = labelsData.split('\n');

      print("Model and labels loaded successfully");
      evaluateModel();
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
    List<double> inputData = List.generate(215, (index) => 0.0); //ONLY 0s

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
    int time = DateTime.now().millisecondsSinceEpoch-timestampBegin;

    setState(() {
      _output = "Predicted: $predictedLabel (Confidence: $confidence , Time: $time)";
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
    return Center(
      child: Text(_output ?? 'Evaluating model...'),
    );
  }
}
