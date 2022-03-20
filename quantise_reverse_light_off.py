import numpy as np
import tensorflow as tf
from tensorflow import keras
import pandas as p
from tensorflow import keras
from tensorflow.keras import layers, regularizers
from tensorflow.keras.layers import Dense, Dropout, Activation, Flatten, BatchNormalization, Input
from tensorflow.keras.layers import Conv2D, MaxPooling2D, LeakyReLU, MaxPooling3D

df = p.read_csv(
    './MAI-Project/combined_reverse_light_off_attack.csv')  # Reading in CSV file
c1 = df.iloc[:, 2]  # Reading in ID and payload

ID = [None] * len(c1)  # Array for all ID's
PL = [None] * len(c1)  # Array for all payloads
TV = np.zeros(len(c1))  # Array for all target variables
y = 0; z = 0  # Variables for attack message sand non-attack messages

# Separating message id and payload
for i in range(0, len(c1)):
    string = c1[i]
    ID[i] = string[0:3]
    PL[i] = string[4:20]

# Creating target variable
for i in range(len(c1)):
    if c1[i][8:10] == "04":
        if c1[i][0:3] == '0D0':
            TV[i] = 1
            y = y + 1
    else:
        TV[i] = 0
        z = z + 1

print('No. of attacks', y)  # Printing number of attacks in the CSV file
print('No. of non attacks', z)  # Printing number of non-attacks in CSV file
ID1 = [None] * len(ID)  # Separated payload 1
ID2 = [None] * len(ID)  # Separated payload 2
ID3 = [None] * len(ID)  # Separated payload 3
IDbin = [None] * len(ID)  # Array for ID's stored in binary format
IDcomb = [None] * len(ID)  # Separated payload 3

# Converting the ID's from HEX to binary
for i in range(0, len(ID)):
    id = ID[i]
    id = int(id, 16)  # Convert ID from HEX to an integer
    id = bin(id)  # Convert the integer to binary
    id = id[2:]  # Delete the '0b' at beginning of binary number
    id = id.zfill(12)  # Zero pad the binary number to 12 bits
    IDbin[i] = id  # Store in the IDbin array
# print(IDbin)

samples = len(c1)  # Number of samples in the dataset
IDs_in_past = 4  # Number of features
Payload_bits = 2  # No. of payload bits use
bit_length = 12  # Number of bits of each feature

x = np.zeros([samples, (IDs_in_past+Payload_bits), bit_length])  # Array containing all feature which is used as input
y = np.zeros([samples, 1])  # Array for target variable

PL1 = [None] * len(c1)  # Payload  hex bit used as feature
PL2 = [None] * len(c1)  # Payload hex bit used as feature

for i in range(len(c1)):
    pl = c1[i]
    payload1 = pl[8:9]  # Payload bit 14
    payload2 = pl[9:10]  # Payload bit 15

    payload1 = int(payload1, 16)  # Convert ID from HEX to an integer
    payload1 = bin(payload1)  # Convert the integer to binary
    payload1 = payload1[2:]  # Delete the '0b' at beginning of binary number
    payload1 = payload1.zfill(12)  # Zero pad the binary number to 12 bits

    payload2 = int(payload2, 16)  # Convert ID from HEX to an integer
    payload2 = bin(payload2)  # Convert the integer to binary
    payload2 = payload2[2:]  # Delete the '0b' at beginning of binary number
    payload2 = payload2.zfill(12)  # Zero pad the binary number to 12 bits

    PL1[i] = payload1  # Store payload 1 in PL1 array
    PL2[i] = payload2  # Store payload 2 in PL2 array


# Creating input array for model
# Adding 4 previous ID's
for i in range((IDs_in_past-1), samples):
    for j in range(IDs_in_past):
        for k in range(bit_length):
            temp = IDbin[i - j]
            x[i][j][k] = temp[k]

# Adding 2 of the current payload bits
for i in range((IDs_in_past-1), len(c1)):
    for k in range(bit_length):
        temp1 = PL1[i]
        temp2 = PL2[i]
        x[i][(IDs_in_past)][k] = temp1[k]
        x[i][(IDs_in_past+1)][k] = temp2[k]

# Adding target variable for group of payload bits - if there is 1 or more attack messages label it as an attack
for i in range((IDs_in_past-1), samples):
    # print(TV[i])
    a = TV[i]  # Current target variable
    b = TV[i - 1]  # Previous target variable
    c = TV[i - 2]  # 2nd Previous target variable
    d = TV[i - 3]  # 3rd Previous target variable
    z = np.sum([a, b, c, d])  # Sum of target variable values
    if z < 1:  # Normal
        y[i] = 0
    if z >= 1:  # Attack
        y[i] = 1

# print('X is', x)
print('X shape', x.shape)  # Printing x shape
# print('y is', y)
print('y shape', y.shape)  # Printing y shape

x = x.astype('i')  # Denoting the variable type of x (input)
y = y.astype('i')  # Denoting the variable type of y (target variable)


test_samples = 500
test_X = np.zeros([test_samples,(IDs_in_past+Payload_bits),12])
for i in range(test_samples):
    test_X[i] = x[i]
test_X = test_X.reshape(test_samples,1,(IDs_in_past+Payload_bits),12)
num_classes = 1
input_shape = (1, (IDs_in_past+Payload_bits), 12)  # Size of input - 6 features x 12 bits

model_input = Input(shape=(1, (IDs_in_past+Payload_bits), 12))
x = Conv2D(16, (3, 3), padding='same', input_shape=input_shape, activation='relu')(model_input)
x = BatchNormalization()(x)
x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

x = Conv2D(32, (3, 3), padding='same', activation='relu')(x)
x = BatchNormalization()(x)
x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

x = Conv2D(64, (3, 3), padding='same', activation='relu')(x)
x = BatchNormalization()(x)
x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

#x = Conv2D(128, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

#x = Conv2D(256, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

x = Flatten()(x)
x = Dense(16, activation='relu', kernel_regularizer=regularizers.l1(0.0001))(x)
x = Dense(num_classes, kernel_regularizer=regularizers.l1(0.0001))(x)
x = Activation(activation='sigmoid')(x) #maybe need to change

model = tf.keras.Model(inputs=model_input, outputs=x, name="conv2D_model")
model.compile(loss="binary_crossentropy", optimizer='adam', metrics=["accuracy"])
model.summary()

float_model = tf.keras.Model(inputs=model_input, outputs=x, name="conv2D_model")
float_model.summary()
path = './reverse_light_off.h5'
float_model.load_weights(path)

#Quantizing the model step.
from tensorflow_model_optimization.quantization.keras import vitis_quantize
quantizer = vitis_quantize.VitisQuantizer(float_model)
quantized_model = quantizer.quantize_model(calib_dataset=test_X)
#quantized_model = quantizer.quantize_model( calib_dataset=test_X, fold_conv_bn=False, fold_bn=False, replace_relu6=False, include_cle=True, cle_steps=10)
quantized_model.save('quantize_reverse_off.h5')

from tensorflow_model_optimization.quantization.keras import vitis_quantize
with vitis_quantize.quantize_scope():
    model = tf.keras.models.load_model('quantize_reverse_off.h5')

model.summary()
