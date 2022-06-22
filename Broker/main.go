package main

import (
	"fmt"
	"io"
	"jk/broker/broker"
	"jk/broker/handlers"
	"jk/broker/pki"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	broker, err := broker.New()
	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		cert, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("No certificate provided"))
			return
		}

		cn, pkey, err := pki.ValidateCertificate(cert)
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Println(err)
			w.Write([]byte("Invalid certificate"))
			return
		}

		vec := handlers.Vehicule{StationID: cn, PublicKey: pkey}
		broker.AddVehiculeToHandler(vec)

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Vehicule authenticated"))
	})

	fmt.Println("Broker Started !")
	go broker.Start()
	fmt.Println("Server Started !")
	if err := http.ListenAndServe("0.0.0.0:9000", router); err != nil {
		log.Fatal(err)
	}
}
