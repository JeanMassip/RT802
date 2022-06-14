FROM python:3
COPY . .
RUN pip install requirements.txt
CMD [ "python", "./GenerateRSAkeys.py" ]
CMD [ "python", "./CSRBuild.py" ]
CMD [ "python", "./VehiculetoGateway.py" ]
