import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, regularizers
from tensorflow.keras.layers import Dense, Dropout, Activation, Flatten, BatchNormalization, Input
from tensorflow.keras.layers import Conv2D, MaxPooling2D, LeakyReLU, MaxPooling3D
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, accuracy_score
import sklearn as skl
import sklearn.model_selection
from sklearn.model_selection import train_test_split
from sklearn.dummy import DummyRegressor
from sklearn.utils import shuffle
import matplotlib.pyplot as plt

plt.rc('font', size=18)
plt.rcParams['figure.constrained_layout.use'] = True
import pandas as p
import sys
import ssl
import time
import sklearn.metrics as metrics
from sklearn.metrics import roc_curve
import matplotlib.patches as mpatches

start_time = time.time()
ssl._create_default_https_context = ssl._create_unverified_context



model = tf.keras.models.load_model('/Users/stephenbyrne/MAIproject/quantize_fuzzing.h5')
model.summary()

preds = model.predict(x_test)
# print('Predictions', preds)
for i in range(len(preds)):
    if preds[i] > .5:
        # print(preds[i], '\n', i)
        preds[i] = 1
    else:
        preds[i] = 0

# Performance metrics
print("X test", x_test)  # Printing input testing set
print("y test", y_test)  # Printing target variable training set
print("predictions", preds)  # Printing predictions after classification
print(classification_report(y_test, preds))  # Printing classification report
print(confusion_matrix(y_test, preds))  # Printing confusion matrix
print("Accuracy:  ", accuracy_score(y_test, preds))  # Accuracy
print("F1 score: ", f1_score(y_test, preds, average="macro"))  # F1 score
print("Precision: ", precision_score(y_test, preds, average="macro"))  # Precision score
print("Recall: ", recall_score(y_test, preds, average="macro"))  # Recall score
tn, fp, fn, tp = confusion_matrix(list(y_test), list(preds), labels=[0, 1]).ravel()
print("False positve rate: ", (fp/(tn+fp)))