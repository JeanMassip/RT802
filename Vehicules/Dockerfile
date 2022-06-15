FROM python:3
COPY . .
RUN pip install -r requirements.txt
RUN python ./GenerateRSAkeys.py
RUN python ./CSRBuild.py
RUN python ./VehiculetoCA.py
CMD [ "python", "./VehiculetoGateway.py", "-t", "ORDINARY" ]
