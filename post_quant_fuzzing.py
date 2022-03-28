import numpy as np
import tensorflow as tf
from tensorflow.keras.optimizers import Adam, SGD, Adadelta
from tensorflow import keras
from tensorflow.keras import applications, Sequential, utils
from tensorflow.keras.layers import Reshape, Input, ReLU, Dense, BatchNormalization, Dropout , TimeDistributed, LSTM, Flatten, Conv2D, MaxPooling2D, ConvLSTM2D, Conv3D, Activation
from tensorflow.keras import regularizers
from tensorflow.keras.regularizers import L1L2
import pandas as p
import os

df = p.read_csv(
    '/Users/stephenbyrne/Documents/College Year 5/Project/Attacks/fuzzing_attack_combined.csv')  # Reading in CSV file
c1 = df.iloc[:, 2]  # Reading in ID and payload

ID = [None] * len(c1)  # Array for all ID's
PL = [None] * len(c1)  # Array for all payloads
TV = np.zeros(len(c1))  # Array for all target variables
y = 0;
z = 0  # Variables for attack message sand non-attack messages

# Separating message id and payload
for i in range(0, len(c1)):
    string = c1[i]
    ID[i] = string[0:3]
    PL[i] = string[4:20]

# Creating target variable
for i in range(len(c1)):
    if c1[i][4:20] == "FFFFFFFFFFFFFFFF":
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
Payload_bits = 64  # No. of payload bits use
bit_length = 12  # Number of bits of each feature

x = np.zeros([samples, (IDs_in_past + Payload_bits), bit_length])  # Array containing all feature which is used as input
y = np.zeros([samples, 1])  # Array for target variable

PL1 = [None] * len(c1)  # Payload  hex bit used as feature
PL2 = [None] * len(c1)  # Payload hex bit used as feature
PL3 = [None] * len(c1)  # Payload hex bit used as feature
PL4 = [None] * len(c1)  # Payload hex bit used as feature
PL5 = [None] * len(c1)  # Payload  hex bit used as feature
PL6 = [None] * len(c1)  # Payload hex bit used as feature
PL7 = [None] * len(c1)  # Payload hex bit used as feature
PL8 = [None] * len(c1)  # Payload hex bit used as feature
PL9 = [None] * len(c1)  # Payload  hex bit used as feature
PL10 = [None] * len(c1)  # Payload hex bit used as feature
PL11 = [None] * len(c1)  # Payload hex bit used as feature
PL12 = [None] * len(c1)  # Payload hex bit used as feature
PL13 = [None] * len(c1)  # Payload  hex bit used as feature
PL14 = [None] * len(c1)  # Payload hex bit used as feature
PL15 = [None] * len(c1)  # Payload hex bit used as feature
PL16 = [None] * len(c1)  # Payload hex bit used as feature

for i in range(len(c1)):
    pl = c1[i]
    payload1 = pl[8:9]  # Payload bit 14
    payload2 = pl[9:10]  # Payload bit 15
    payload3 = pl[10:11]  # Payload bit 15
    payload4 = pl[11:12]  # Payload bit 15
    payload5 = pl[12:13]  # Payload bit 14
    payload6 = pl[13:14]  # Payload bit 15
    payload7 = pl[14:15]  # Payload bit 15
    payload8 = pl[15:16]  # Payload bit 15
    payload9 = pl[4:5]  # Payload bit 14
    payload10 = pl[5:6]  # Payload bit 15
    payload11 = pl[6:7]  # Payload bit 15
    payload12 = pl[16:17]  # Payload bit 15
    payload13 = pl[17:18]  # Payload bit 14
    payload14 = pl[18:19]  # Payload bit 15
    payload15 = pl[19:20]  # Payload bit 15
    payload16 = pl[7:8]  # Payload bit 15

    payload1 = int(payload1, 16)  # Convert ID from HEX to an integer
    payload1 = bin(payload1)  # Convert the integer to binary
    payload1 = payload1[2:]  # Delete the '0b' at beginning of binary number
    payload1 = payload1.zfill(12)  # Zero pad the binary number to 12 bits

    payload2 = int(payload2, 16)  # Convert ID from HEX to an integer
    payload2 = bin(payload2)  # Convert the integer to binary
    payload2 = payload2[2:]  # Delete the '0b' at beginning of binary number
    payload2 = payload2.zfill(12)  # Zero pad the binary number to 12 bits

    payload3 = int(payload3, 16)  # Convert ID from HEX to an integer
    payload3 = bin(payload3)  # Convert the integer to binary
    payload3 = payload3[2:]  # Delete the '0b' at beginning of binary number
    payload3 = payload3.zfill(12)  # Zero pad the binary number to 12 bits

    payload4 = int(payload4, 16)  # Convert ID from HEX to an integer
    payload4 = bin(payload4)  # Convert the integer to binary
    payload4 = payload4[2:]  # Delete the '0b' at beginning of binary number
    payload4 = payload4.zfill(12)  # Zero pad the binary number to 12 bits

    payload5 = int(payload5, 16)  # Convert ID from HEX to an integer
    payload5 = bin(payload5)  # Convert the integer to binary
    payload5 = payload5[2:]  # Delete the '0b' at beginning of binary number
    payload5 = payload5.zfill(12)  # Zero pad the binary number to 12 bits

    payload6 = int(payload6, 16)  # Convert ID from HEX to an integer
    payload6 = bin(payload6)  # Convert the integer to binary
    payload6 = payload6[2:]  # Delete the '0b' at beginning of binary number
    payload6 = payload6.zfill(12)  # Zero pad the binary number to 12 bits

    payload7 = int(payload7, 16)  # Convert ID from HEX to an integer
    payload7 = bin(payload7)  # Convert the integer to binary
    payload7 = payload7[2:]  # Delete the '0b' at beginning of binary number
    payload7 = payload7.zfill(12)  # Zero pad the binary number to 12 bits

    payload8 = int(payload8, 16)  # Convert ID from HEX to an integer
    payload8 = bin(payload8)  # Convert the integer to binary
    payload8 = payload8[2:]  # Delete the '0b' at beginning of binary number
    payload8 = payload8.zfill(12)  # Zero pad the binary number to 12 bits

    payload9 = int(payload9, 16)  # Convert ID from HEX to an integer
    payload9 = bin(payload9)  # Convert the integer to binary
    payload9 = payload9[2:]  # Delete the '0b' at beginning of binary number
    payload9 = payload9.zfill(12)  # Zero pad the binary number to 12 bits

    payload10 = int(payload10, 16)  # Convert ID from HEX to an integer
    payload10 = bin(payload10)  # Convert the integer to binary
    payload10 = payload10[2:]  # Delete the '0b' at beginning of binary number
    payload10 = payload10.zfill(12)  # Zero pad the binary number to 12 bits

    payload11 = int(payload11, 16)  # Convert ID from HEX to an integer
    payload11 = bin(payload11)  # Convert the integer to binary
    payload11 = payload11[2:]  # Delete the '0b' at beginning of binary number
    payload11 = payload11.zfill(12)  # Zero pad the binary number to 12 bits

    payload12 = int(payload12, 16)  # Convert ID from HEX to an integer
    payload12 = bin(payload12)  # Convert the integer to binary
    payload12 = payload12[2:]  # Delete the '0b' at beginning of binary number
    payload12 = payload12.zfill(12)  # Zero pad the binary number to 12 bits

    payload13 = int(payload13, 16)  # Convert ID from HEX to an integer
    payload13 = bin(payload13)  # Convert the integer to binary
    payload13 = payload13[2:]  # Delete the '0b' at beginning of binary number
    payload13 = payload13.zfill(12)  # Zero pad the binary number to 12 bits

    payload14 = int(payload14, 16)  # Convert ID from HEX to an integer
    payload14 = bin(payload14)  # Convert the integer to binary
    payload14 = payload14[2:]  # Delete the '0b' at beginning of binary number
    payload14 = payload14.zfill(12)  # Zero pad the binary number to 12 bits

    payload15 = int(payload15, 16)  # Convert ID from HEX to an integer
    payload15 = bin(payload15)  # Convert the integer to binary
    payload15 = payload15[2:]  # Delete the '0b' at beginning of binary number
    payload15 = payload15.zfill(12)  # Zero pad the binary number to 12 bits

    payload16 = int(payload16, 16)  # Convert ID from HEX to an integer
    payload16 = bin(payload16)  # Convert the integer to binary
    payload16 = payload16[2:]  # Delete the '0b' at beginning of binary number
    payload16 = payload16.zfill(12)  # Zero pad the binary number to 12 bits

    PL1[i] = payload1  # Store payload 1 in PL1 array
    PL2[i] = payload2  # Store payload 2 in PL2 array
    PL3[i] = payload3  # Store payload 1 in PL1 array
    PL4[i] = payload4  # Store payload 2 in PL2 array
    PL5[i] = payload5  # Store payload 1 in PL1 array
    PL6[i] = payload6  # Store payload 2 in PL2 array
    PL7[i] = payload7  # Store payload 1 in PL1 array
    PL8[i] = payload8  # Store payload 2 in PL2 array
    PL9[i] = payload9  # Store payload 1 in PL1 array
    PL10[i] = payload10  # Store payload 2 in PL2 array
    PL11[i] = payload11  # Store payload 1 in PL1 array
    PL12[i] = payload12  # Store payload 2 in PL2 array
    PL13[i] = payload13  # Store payload 1 in PL1 array
    PL14[i] = payload14  # Store payload 2 in PL2 array
    PL15[i] = payload15  # Store payload 1 in PL1 array
    PL16[i] = payload16  # Store payload 2 in PL2 array

# Creating input array for model
# Adding 4 previous ID's
for i in range((IDs_in_past - 1), samples):
    for j in range(IDs_in_past):
        for k in range(bit_length):
            temp = IDbin[i - j]
            x[i][j][k] = temp[k]

# Adding 2 of the current payload bits
for i in range((IDs_in_past - 1), len(c1)):
    for k in range(bit_length):
        temp1 = PL1[i]
        temp2 = PL2[i]
        temp3 = PL3[i]
        temp4 = PL4[i]
        temp5 = PL5[i]
        temp6 = PL6[i]
        temp7 = PL7[i]
        temp8 = PL8[i]
        temp9 = PL9[i]
        temp10 = PL10[i]
        temp11 = PL11[i]
        temp12 = PL12[i]
        temp13 = PL13[i]
        temp14 = PL14[i]
        temp15 = PL15[i]
        temp16 = PL16[i]

        temp1a = PL1[i - 1]
        temp2a = PL2[i - 1]
        temp3a = PL3[i - 1]
        temp4a = PL4[i - 1]
        temp5a = PL5[i - 1]
        temp6a = PL6[i - 1]
        temp7a = PL7[i - 1]
        temp8a = PL8[i - 1]
        temp9a = PL9[i - 1]
        temp10a = PL10[i - 1]
        temp11a = PL11[i - 1]
        temp12a = PL12[i - 1]
        temp13a = PL13[i - 1]
        temp14a = PL14[i - 1]
        temp15a = PL15[i - 1]
        temp16a = PL16[i - 1]

        temp1b = PL1[i - 2]
        temp2b = PL2[i - 2]
        temp3b = PL3[i - 2]
        temp4b = PL4[i - 2]
        temp5b = PL5[i - 2]
        temp6b = PL6[i - 2]
        temp7b = PL7[i - 2]
        temp8b = PL8[i - 2]
        temp9b = PL9[i - 2]
        temp10b = PL10[i - 2]
        temp11b = PL11[i - 2]
        temp12b = PL12[i - 2]
        temp13b = PL13[i - 2]
        temp14b = PL14[i - 2]
        temp15b = PL15[i - 2]
        temp16b = PL16[i - 2]

        temp1c = PL1[i - 3]
        temp2c = PL2[i - 3]
        temp3c = PL3[i - 3]
        temp4c = PL4[i - 3]
        temp5c = PL5[i - 3]
        temp6c = PL6[i - 3]
        temp7c = PL7[i - 3]
        temp8c = PL8[i - 3]
        temp9c = PL9[i - 3]
        temp10c = PL10[i - 3]
        temp11c = PL11[i - 3]
        temp12c = PL12[i - 3]
        temp13c = PL13[i - 3]
        temp14c = PL14[i - 3]
        temp15c = PL15[i - 3]
        temp16c = PL16[i - 3]

        x[i][IDs_in_past][k] = temp1[k]
        x[i][(IDs_in_past + 1)][k] = temp2[k]
        x[i][(IDs_in_past + 2)][k] = temp3[k]
        x[i][(IDs_in_past + 3)][k] = temp4[k]
        x[i][(IDs_in_past + 4)][k] = temp5[k]
        x[i][(IDs_in_past + 5)][k] = temp6[k]
        x[i][(IDs_in_past + 6)][k] = temp7[k]
        x[i][(IDs_in_past + 7)][k] = temp8[k]
        x[i][(IDs_in_past + 8)][k] = temp9[k]
        x[i][(IDs_in_past + 9)][k] = temp10[k]
        x[i][(IDs_in_past + 10)][k] = temp11[k]
        x[i][(IDs_in_past + 11)][k] = temp12[k]
        x[i][(IDs_in_past + 12)][k] = temp13[k]
        x[i][(IDs_in_past + 13)][k] = temp14[k]
        x[i][(IDs_in_past + 14)][k] = temp15[k]
        x[i][(IDs_in_past + 15)][k] = temp16[k]

        x[i][(IDs_in_past + 16)][k] = temp1a[k]
        x[i][(IDs_in_past + 17)][k] = temp2a[k]
        x[i][(IDs_in_past + 18)][k] = temp3a[k]
        x[i][(IDs_in_past + 19)][k] = temp4a[k]
        x[i][(IDs_in_past + 20)][k] = temp5a[k]
        x[i][(IDs_in_past + 21)][k] = temp6a[k]
        x[i][(IDs_in_past + 22)][k] = temp7a[k]
        x[i][(IDs_in_past + 23)][k] = temp8a[k]
        x[i][(IDs_in_past + 24)][k] = temp9a[k]
        x[i][(IDs_in_past + 25)][k] = temp10a[k]
        x[i][(IDs_in_past + 26)][k] = temp11a[k]
        x[i][(IDs_in_past + 27)][k] = temp12a[k]
        x[i][(IDs_in_past + 28)][k] = temp13a[k]
        x[i][(IDs_in_past + 29)][k] = temp14a[k]
        x[i][(IDs_in_past + 30)][k] = temp15a[k]
        x[i][(IDs_in_past + 31)][k] = temp16a[k]

        x[i][(IDs_in_past + 32)][k] = temp1b[k]
        x[i][(IDs_in_past + 33)][k] = temp2b[k]
        x[i][(IDs_in_past + 34)][k] = temp3b[k]
        x[i][(IDs_in_past + 35)][k] = temp4b[k]
        x[i][(IDs_in_past + 36)][k] = temp5b[k]
        x[i][(IDs_in_past + 37)][k] = temp6b[k]
        x[i][(IDs_in_past + 38)][k] = temp7b[k]
        x[i][(IDs_in_past + 39)][k] = temp8b[k]
        x[i][(IDs_in_past + 40)][k] = temp9b[k]
        x[i][(IDs_in_past + 41)][k] = temp10b[k]
        x[i][(IDs_in_past + 42)][k] = temp11b[k]
        x[i][(IDs_in_past + 43)][k] = temp12b[k]
        x[i][(IDs_in_past + 44)][k] = temp13b[k]
        x[i][(IDs_in_past + 45)][k] = temp14b[k]
        x[i][(IDs_in_past + 46)][k] = temp15b[k]
        x[i][(IDs_in_past + 47)][k] = temp16b[k]

        x[i][(IDs_in_past + 48)][k] = temp1c[k]
        x[i][(IDs_in_past + 49)][k] = temp2c[k]
        x[i][(IDs_in_past + 50)][k] = temp3c[k]
        x[i][(IDs_in_past + 51)][k] = temp4c[k]
        x[i][(IDs_in_past + 52)][k] = temp5c[k]
        x[i][(IDs_in_past + 53)][k] = temp6c[k]
        x[i][(IDs_in_past + 54)][k] = temp7c[k]
        x[i][(IDs_in_past + 55)][k] = temp8c[k]
        x[i][(IDs_in_past + 56)][k] = temp9c[k]
        x[i][(IDs_in_past + 57)][k] = temp10c[k]
        x[i][(IDs_in_past + 58)][k] = temp11c[k]
        x[i][(IDs_in_past + 59)][k] = temp12c[k]
        x[i][(IDs_in_past + 60)][k] = temp13c[k]
        x[i][(IDs_in_past + 61)][k] = temp14c[k]
        x[i][(IDs_in_past + 62)][k] = temp15c[k]
        x[i][(IDs_in_past + 63)][k] = temp16c[k]

# Adding target variable for group of payload bits - if there is 1 or more attack messages label it as an attack
for i in range((IDs_in_past - 1), samples):
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

# x_train, x_test, y_train, y_test = skl.model_selection.train_test_split(x, y, test_size=.1,
# random_state=0)  # Splitting data into training and testing

train_prop = 0.8
test_prop = 0.1
val_prop = 0.1

x_train_size = int(train_prop * len(c1))
x_test_size = int(test_prop * len(c1))
x_val_size = int(val_prop * len(c1)) + 2

x_train = np.zeros([x_train_size, (IDs_in_past + Payload_bits), bit_length])
y_train = np.zeros([x_train_size, 1])
x_test = np.zeros([x_test_size, (IDs_in_past + Payload_bits), bit_length])
y_test = np.zeros([x_test_size, 1])
x_val = np.zeros([x_val_size, (IDs_in_past + Payload_bits), bit_length])
y_val = np.zeros([x_val_size, 1])

# Manually splitting up testing, train and validation sets
# Training set is the first 80%
for index in range(0, x_train_size):
    x_train[index] = x[index]
    y_train[index] = y[index]

# Testing set is the next 10%
for index in range(x_train_size, (x_train_size + x_test_size)):
    x_test[index - x_train_size] = x[index]
    y_test[index - x_train_size] = y[index]

# Validation set is the final 10%
for index in range((x_train_size + x_test_size), len(c1)):
    x_val[index - (x_train_size + x_test_size)] = x[index]
    y_val[index - (x_train_size + x_test_size)] = y[index]

'''
print('x', x)
print('x_train', x_train)
print('y_train', y_train)
print('x_test', x_test)
print('y_test', y_test)
print('x_val', x_val)
print('y_val', y_val)

print(len(x_train))
print(len(y_train))
print(len(x_test))
print(len(y_test))
print(len(x_val))
print(len(y_val))
'''
# Model / data parameters
num_classes = 1  # Number of classes needed to be predicted - 1
input_shape = (1, (IDs_in_past + Payload_bits), 12)  # Size of input - 6 features x 12 bits

print("orig x_train shape:", x_train.shape)  # Printing shape of the x training set
print("length of testing", len(x_test))  # Printing length of the x testing set
print("length of training", len(x_train))  # Printing length of the x training set
# print("x train", x_train)
# print("y_train", y_train)

# Reshaping inputs for the model
x_train = x_train.reshape(len(x_train), 1, (IDs_in_past + Payload_bits), 12)
x_test = x_test.reshape(len(x_test), 1, (IDs_in_past + Payload_bits), 12)
y_train = y_train.reshape(len(y_train), 1)
y_test = y_test.reshape(len(y_test), 1)


# Model definition
model_input = Input(shape=(1, (IDs_in_past + Payload_bits), 12))
x = Conv2D(16, (3, 3), padding='same', input_shape=input_shape, activation='relu')(model_input)
x = BatchNormalization()(x)
x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

x = Conv2D(32, (3, 3), padding='same', activation='relu')(x)
x = BatchNormalization()(x)
x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

#x = Conv2D(64, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

#x = Conv2D(128, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

#x = Conv2D(256, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)

x = Flatten()(x)
#x = Dense(16, activation='relu', kernel_regularizer=regularizers.l1(0.0001))(x)
x = Dense(num_classes, kernel_regularizer=regularizers.l1(0.0001))(x)
x = Activation(activation='sigmoid')(x)

# model = tf.keras.Model(inputs=model_input, outputs=x, name="conv2dmodel")
# model.summary()

# *Call Vai_q_tensorflow2 api to create the quantize training model
# from tensorflow_model_optimization.quantization.keras import vitis_quantize
# quantizer = vitis_quantize.VitisQuantizer(model)
# model = quantizer.get_qat_model()

from tensorflow_model_optimization.quantization.keras import vitis_quantize
with vitis_quantize.quantize_scope():
    model = tf.keras.models.load_model('quantize_fuzzing.h5')

model.summary()

# Compile the model
model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001), loss='binary_crossentropy', metrics=['accuracy'])
### Callback
checkpoint_dir = 'PQ_Fuzzing'
os.mkdir(checkpoint_dir)

cp_callback = tf.keras.callbacks.ModelCheckpoint(filepath =checkpoint_dir + '/weights.{epoch:03d}.h5',
                                                 verbose = 1,
                                                 save_best_only=True,
                                                 save_weights_only=False,
                                                 mode='auto')
earlystopping_callback = tf.keras.callbacks.EarlyStopping(
        monitor = 'val_loss',
        patience = 5,
        mode='auto',
        verbose = 1)
model.fit(x_train, y_train, batch_size=64, epochs=5,validation_split=0.15,callbacks = [ cp_callback,earlystopping_callback])
#model.save('trained_model.h5')