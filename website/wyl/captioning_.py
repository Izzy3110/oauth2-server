import numpy
from keras import Sequential
from tensorflow import keras
from keras.constraints import maxnorm
from keras.utils import np_utils
from keras.datasets import cifar10
import pandas as pd
import matplotlib.pyplot as plt

# Loading in the data
(X_train, y_train), (X_test, y_test) = cifar10.load_data()

# Set random seed for purposes of reproducibility
seed = 21

# Normalize the inputs from 0-255 to between 0 and 1 by dividing by 255
X_train = X_train.astype('float32')
X_test = X_test.astype('float32')
X_train = X_train / 255.0
X_test = X_test / 255.0

# One-hot encode outputs
y_train = np_utils.to_categorical(y_train)
y_test = np_utils.to_categorical(y_test)
class_num = y_test.shape[1]

model = keras.Sequential([
    keras.layers.Conv2D(32, 3, input_shape=(32, 32, 3), activation='relu', padding='same'),
    keras.layers.Dropout(0.2),
    keras.layers.BatchNormalization(),

    keras.layers.Conv2D(64, (3, 3), padding='same', activation='relu'),
    keras.layers.MaxPooling2D(2),
    keras.layers.Dropout(0.2),
    keras.layers.BatchNormalization(),

    keras.layers.Conv2D(64, 3, padding='same', activation='relu'),
    keras.layers.MaxPooling2D(2),
    keras.layers.Dropout(0.2),
    keras.layers.BatchNormalization(),

    keras.layers.Conv2D(128, (3, 3), padding='same', activation='relu'),
    keras.layers.Dropout(0.2),
    keras.layers.BatchNormalization(),

    keras.layers.Flatten(),
    keras.layers.Dropout(0.2),
    keras.layers.Dense(32, activation='relu'),
    keras.layers.Dropout(0.3),
    keras.layers.BatchNormalization(),

    keras.layers.Dense(class_num, activation='softmax'),
])


model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

print(model.summary())


numpy.random.seed(seed)
history = model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=25, batch_size=64)

model.evaluate(X_test, y_test, verbose=0)

pd.DataFrame(history.history).plot()
plt.show()
