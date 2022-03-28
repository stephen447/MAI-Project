import numpy as np
import tensorflow as tf
from tensorflow.keras.optimizers import Adam, SGD, Adadelta
from tensorflow import keras
from tensorflow.keras import applications, Sequential, utils
from tensorflow.keras.layers import Reshape, Input, ReLU, Dense, BatchNormalization, Dropout , TimeDistributed, LSTM, Flatten, Conv2D, MaxPooling2D, ConvLSTM2D, Conv3D, Activation
from tensorflow.keras import regularizers
from tensorflow.keras.regularizers import L1L2
import os
import pandas as p

df = p.read_csv(
    '/Users/stephenbyrne/Documents/College Year 5/Project/Attacks/combined_reverse_light_on_attack.csv')  # Reading in CSV file
c1 = df.iloc[:, 2]  # Reading in ID and payload

ID = [None] * len(c1)  # Array for all ID's
PL = [None] * len(c1)  # Array for all payloads
TV = np.zeros(len(c1))  # Array for all target variables
y = 0;z = 0  # Variables for attack message sand non-attack messages

# Separating message id and payload
for i in range(0, len(c1)):
    string = c1[i]
    ID[i] = string[0:3]
    PL[i] = string[4:20]

# Creating target variable
for i in range(len(c1)):
    if c1[i][8:10] == "0C":
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

train_prop = 0.8
test_prop = 0.1
val_prop = 0.1

x_train_size = int(train_prop*len(c1))
x_test_size = int(test_prop*len(c1))
x_val_size = int(val_prop*len(c1))+2

x_train = np.zeros([x_train_size, (IDs_in_past+Payload_bits), bit_length])
y_train = np.zeros([x_train_size, 1])
x_test = np.zeros([x_test_size, (IDs_in_past+Payload_bits), bit_length])
y_test = np.zeros([x_test_size, 1])
x_val = np.zeros([x_val_size, (IDs_in_past+Payload_bits), bit_length])
y_val = np.zeros([x_val_size, 1])

for index in range(0, x_train_size):
    x_train[index] = x[index]
    y_train[index] = y[index]

for index in range(x_train_size, (x_train_size+x_test_size)):
    x_test[index-x_train_size] = x[index]
    y_test[index-x_train_size] = y[index]

for index in range((x_train_size+x_test_size), len(c1)):
    x_val[index-(x_train_size+x_test_size)] = x[index]
    y_val[index-(x_train_size+x_test_size)] = y[index]

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
input_shape = (1, (IDs_in_past+Payload_bits), 12)  # Size of input - 6 features x 12 bits

print("orig x_train shape:", x_train.shape)  # Printing shape of the x training set
print("length of testing", len(x_test))  # Printing length of the x testing set
print("length of training", len(x_train))  # Printing length of the x training set
# print("x train", x_train)
# print("y_train", y_train)

# Reshaping inputs for the model
x_train = x_train.reshape(len(x_train), 1, (IDs_in_past+Payload_bits), 12)
x_test = x_test.reshape(len(x_test), 1, (IDs_in_past+Payload_bits), 12)
y_train = y_train.reshape(len(y_train), 1)
y_test = y_test.reshape(len(y_test), 1)


# Model definition
model_input = Input(shape=(1, (IDs_in_past + Payload_bits), 12))
x = Conv2D(16, (3, 3), padding='same', input_shape=input_shape, activation='relu')(model_input)
x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)
#x = Dropout(0.5)(x)

x = Conv2D(32, (3, 3), padding='same', activation='relu')(x)
x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)
#x = Dropout(0.5)(x)

x = Conv2D(64, (3, 3), padding='same', activation='relu')(x)
x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)
#x = Dropout(0.5)(x)

#x = Conv2D(128, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)
#x = Dropout(0.5)(x)

#x = Conv2D(256, (3, 3), padding='same', activation='relu')(x)
#x = BatchNormalization()(x)
#x = MaxPooling2D(pool_size=(2, 2), padding='Same')(x)
#x = Dropout(0.5)(x)

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
    model = tf.keras.models.load_model('quantize_reverse_on.h5')

model.summary()

# Compile the model
model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001), loss='binary_crossentropy', metrics=['accuracy'])
### Callback
checkpoint_dir = 'PQ_reverse_on'
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