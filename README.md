# Detecting Mobile Device Malware Using Computation and Battery-Sensitive Machine Learning Techniques
Graduation project for the University of Aberdeen MSc Cyber Security course. **NOTE:** This is chatgippidied readme. I'll probably upload my thesis in some form here instead after graduation.

## Overview
This repository contains an Android malware detection application that leverages advanced AI techniques to identify malicious applications. The project involves training AI models using datasets on PyTorch and Azure ML Studio, which are then integrated into a Flutter app powered by TensorFlow Lite for real-time malware detection on Android devices.

## Project Structure (branches)
- **AI Model Training**: The AI models are trained using the Malgenome and MH100k datasets on PyTorch and Azure ML Studio. 
- **Flutter Apps**: The trained models are deployed in a Flutter application using TensorFlow Lite for on-device inference and malware detection.

## Datasets
### Malgenome
The Malgenome project provides a comprehensive Android malware dataset that is crucial for training robust AI models.

- [Malgenome Project Homepage](http://www.malgenomeproject.org/)
- [Malgenome Dataset on Figshare](https://figshare.com/articles/dataset/Android_malware_dataset_for_machine_learning_1/5854590)

### MH100k
MH100k is another extensive dataset that contains a wealth of Android malware samples, enriching the training data for our models.

- [MH100k Article on ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2352340923008193)
- [MH100k Dataset on Figshare](https://figshare.com/articles/dataset/Android_malware_dataset_for_machine_learning_1/5854590)

## Technologies Used
- **PyTorch**: Used for developing and training the deep learning models.
- **Azure ML Studio**: Facilitates scalable training and model management.
- **Flutter**: A UI toolkit for building natively compiled applications for mobile from a single codebase.
- **TensorFlow Lite**: Used for deploying AI models on mobile devices for real-time inference.
