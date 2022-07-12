# Trellix Analytic Service Integrator
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This service provides the ability to integrate various Trellix solutions with Malware Analytic Services such as Detection-On-Demand (Detection as a Service). The following two use cases are implemented in the current design.

1. Integrates Trellix Endpoint and Trellix TIE (Threat Intelligence Exchange) with Trellix DoD (Detection-On-Demand).
2. Integrates Skyhigh Web Gateway with Trellix DoD (Detection-On-Demand).

This service is written as a flask web application that simulates the ATD|TIS (Advanced Threat Detection | Trellix Intelligence Sandbox) APIs. 
This service can be used with every Trellix solution that natively integrates with ATD|TIS.

## Installation

This is proof of concept code only. In production please make sure to not store username, password and API keys in clear text inside the script.

1. Install > Python3.6

2. Make sure the following dependencies are installed

   ```
   python3 -m pip install requests flask
   ```

3. Place the app.py and report.json in a folder and browse to that folder location (e.g. location /opt/app/)

   ```
   cd /opt/app/
   ```
   
4. Enter a username and password in line 17 and 18. This username and password will need to be the same as configured in TIE and MWG.

   <img width="800" alt="1" src="https://user-images.githubusercontent.com/25227268/178490885-6313649d-9f54-48fb-89fe-cb41d9f7b574.png">
   
5. Generate an API Key in DOD and enter this key in line 21. 

6. Run the flask app with the following command. Specify the listening IP address and Port. (e.g. listen on all IPs and port 8080)

   ```
   flask run --host 0.0.0.0 --port 8080
   ```
   
## Trellix TIE Configuration

1. Open the TIE Server Policy in EPO and select the Sandboxing Tab inside the policy.

2. Enter the username and password entered in Installation Step 4.

   <img width="800" alt="2" src="https://user-images.githubusercontent.com/25227268/178493586-41bc486d-adcf-41a2-9461-5e00adf7a0fc.png">
   
3. Configure the IP address and Port to point to the Flask Application.

## Skyhigh Web Gateway Configuration

1. Open the Web Gateway Policy and import a new Rule Set from the Library.

2. Add the Advanced Threat Detection Rule Set or modify the existing ATD policy.

   <img width="800" alt="3" src="https://user-images.githubusercontent.com/25227268/178501940-64104886-0f1d-44c4-83ea-90f208617c48.png">
   
3. Configure the Policy to point to the Flask App and enter the username and password entered in Installation Step 4.

   <img width="800" alt="4" src="https://user-images.githubusercontent.com/25227268/178503192-7ab4a74b-c990-49a6-a9fb-d2ed57b78cdf.png">
   
