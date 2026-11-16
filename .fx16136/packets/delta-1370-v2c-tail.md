## Risks
- F1/F2: a log with non-finite or unusable times now gives INCONCLUSIVE instead of PASS. That is intended: it fails closed.
- F3: a docker that reports DriverStatus rows other than name/value pairs now refuses the disk gate and pin. That also fails closed.
- Nothing is merged, tagged or deployed.
