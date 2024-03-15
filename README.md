<div align="center">
    <h1>Decentralized Air Quality Classifier</h1>
    <i>A Decentralized Air Quality Index Predictor using sensor values for a list of pollutants</i>
</div>
<div align="center">
  This repository contains an Machine Learning DApp developed using cartesi rollups.
</div>

<div align="center">
  
  <a href="">[![Static Badge](https://img.shields.io/badge/cartesi--rollups-1.0.0-5bd1d7)](https://docs.cartesi.io/cartesi-rollups/)</a>
  <a href="">[![Static Badge](https://img.shields.io/badge/python-3.11-yellow)](https://www.python.org/)</a>
  <a href="">[![Static Badge](https://img.shields.io/badge/Sunodo-0.10.4-red)](https://docs.sunodo.io/guide/introduction/what-is-sunodo)</a>
</div>

This example shows a simple way of leveraging some of the most widely used Machine Learning libraries available in Python.

The DApp generates a [linear regression](https://en.wikipedia.org/wiki/Logistic_regression) model using [scikit-learn](https://scikit-learn.org/), [NumPy](https://numpy.org/) and [pandas](https://pandas.pydata.org/), and then uses [m2cgen (Model to Code Generator)](https://github.com/BayesWitnesses/m2cgen) to transpile that model into native Python code with no dependencies.
This approach is inspired by [Davis David's Machine Learning tutorial](https://www.freecodecamp.org/news/transform-machine-learning-models-into-native-code-with-zero-dependencies/), and is useful for a Cartesi DApp because it removes the need of porting all those Machine Learning libraries to the Cartesi Machine's RISC-V architecture, making the development process easier and the final back-end code simpler to execute.

The practical goal of this application is to predict a classification based on the [Air Quality Dataset](https://www.kaggle.com/datasets/fedesoriano/air-quality-data-set/), which contains the responses of a gas multisensor device deployed on the field in an Italian city. Hourly response averages are recorded along with gas concentration references from a certified analyzer.

The model currently takes into account several variables for predicting the AQI(Air quality index):

1. PT08.S1(CO): This represents the sensor response to Carbon Monoxide (CO) levels in the air.

2. PT08.S2(NMHC): This represents the sensor response to Non-Methane Hydrocarbons (NMHC) in the air. For instance, the value 1046 is the sensor reading, which can be correlated to the actual concentration of NMHC in micrograms per cubic meter (µg/m³).

3. PT08.S3(NOx): This represents the sensor response to Nitrogen Oxides (NOx) in the air. For instance, the value 1056 is the sensor reading, which can be correlated to the actual concentration of NOx in parts per billion (ppb).

4. PT08.S4(NO2): This represents the sensor response to Nitrogen Dioxide (NO2) in the air. For instance, the value 1692 is the sensor reading, which can be correlated to the actual concentration of NO2 in micrograms per cubic meter (µg/m³).

5. PT08.S5(O3): This represents the sensor response to Ozone (O3) in the air. For instance, the value 1268 is the sensor reading, which can be correlated to the actual concentration of O3 in micrograms per cubic meter (µg/m³).

6. T: This represents the temperature in degrees Celsius. For instance, the value 21.6 is the measured temperature.

7. RH: This represents the Relative Humidity in percentage. For instance, the value 13.6 is the measured relative humidity.

8. AH: This represents Absolute Humidity, which is the total water content in the air. For instance, the value 0.76 could be the absolute humidity in grams per cubic meter (g/m³).

As such, inputs to the DApp should be given as a JSON string such as the following:

```json
{"PT08.S1(CO)": 1360, "PT08.S2(NMHC)": 1046, "PT08.S3(NOx)": 1056, "PT08.S4(NO2)": 1692, "PT08.S5(O3)": 1268, "T": 21.6, "RH": 13.6, "AH": 0.76}
```

## Interacting with the application

We have two main ways to interact with the dapp: using the [frontend-web-cartesi](https://github.com/prototyp3-dev/frontend-web-cartesi/tree/0dc77b05ea1288bc2b943cdffe8db9645b669ff6) application, or using the [sunodo send command](https://docs.sunodo.io/guide/running/sending-inputs). 

### frontend-web-cartesi
Clone the repository in the above link.
After that, go to a separate terminal window and switch to the `frontend-web-cartesi` directory:

```shell
cd frontend-web-cartesi
```
Run the following commands to run the frontend web in your localhost:
```
yarn
yarn codegen
yarn start
```
Runs the app in the development mode.
Open http://localhost:3000 to view it in the browser.

Please keep in mind that you should import one of the local wallets to the metamask.With that in place, also add the sunodo token to your wallet. 

**Note: you must deposit some Sunodo tokens to the wallet inside the dApp to be able to use the AQI prediction fuction. **


## Changing the application

This DApp was implemented in a rather generic way and, as such, it is possible to easily change the target dataset as well as the predictor algorithm.

To change those, open the file `airquality/model/build_model.py` and change the following variables defined at the beginning of the script:

- `model`: defines the scikit-learn predictor algorithm to use. While it currently uses `sklearn.linear_model.LinearRegression`, many [other possibilities](https://scikit-learn.org/stable/modules/classes.html) are available, from several types of linear regressions to solutions such as support vector machines (SVMs).
- `train_csv`: a URL or file path to a CSV file containing the dataset. It should contain a first row with the feature names, followed by the data.