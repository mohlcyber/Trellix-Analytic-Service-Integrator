# Trellix Analytic Service Integrator

This service provides the ability to integrate various Trellix solutions with Malware Analytic Services such as Detection-On-Demand (Detection as a Service). The following two use cases are implemented in the current design.

1. Integrates Trellix Endpoint and TIE (Threat Intelligence Exchange) with DoD (Detection-On-Demand).
2. Integrates Skyhigh Web Gateway with DoD (Detection-On-Demand).

This service is written as a flask web application that simulates the ATD|TIS (Advanced Threat Detection | Trellix Intelligence Sandbox) APIs. 
This service can be used with every Trellix solution that natively integrates with ATD|TIS.


