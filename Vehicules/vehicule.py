from email import message
import random
import json
import os

from enum import Enum
from paho.mqtt import client as mqtt


class VehiculeType(int, Enum):
    ORDINARY = 5
    EMERGENCY = 10
    OPERATOR = 15

class Vehicule:
    def __init__(self, stationID: str, stationType: VehiculeType) -> None:
        self.stationID = stationID
        self.stationType = stationType
        self.heading = random.choice([0, 180])

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print("Connected to MQTT Broker!")
            else:
                print("Failed to connect, return code %d\n", rc)

        self.client = mqtt.Client(f'mqtt-station-{stationID}')
        #client.username_pw_set(username, password)
        self.client.on_connect = on_connect
        self.client.connect("127.0.0.1")

    def __del__(self):
        self.client.disconnect()

    def default(self) -> str:
        message = {
            "message": {
                "station_id": self.stationID,
                "station_type": self.stationType,
                "speed": random.randint(80, 90),
                "heading": self.heading,
                "position": "une position"
            }
        }

        return message
        # self.send_message(message, "/sensors/cam")

    def slowed(self) -> None:
        message = {
            "message": {
                "station_id": self.stationID,
                "station_type": self.stationType,
                "speed": random.randint(20, 30),
                "heading": self.heading,
                "position": "une position"
            }
        }

        self.send_message(message, "/sensors/cam")

    def send_message(self, message: dict, topic: str) -> None:
        msg = json.dumps(message)
        result = self.client.publish(topic, msg)
        status = result[0]
        if status == 0:
            print(f"Message sent !")
        else:
            print(f"Failed to send message...")
