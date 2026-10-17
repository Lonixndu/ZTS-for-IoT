package main

import (
	"encoding/json" // read and write JSON
	"flag"          // read command-line options such as -addr
	"log"           // print messages and stop on fatal errors
	"net/http"      // built-in web server
	"strconv"       // convert numbers and booleans to text
	"strings"       // text helpers (TrimPrefix, Contains)

	"github.com/hyperledger/fabric-contract-api-go/contractapi" // Fabric contract library
	"github.com/ztiot/ztiot-cc/contracts"                       // our smart contracts
	"github.com/ztiot/ztiot-cc/fakestub"                        // our in-memory fake ledger (also used by the unit tests)
)

// Package-level variables shared by all HTTP handlers.
var (
	cc     *contractapi.ContractChaincode // the chaincode built from our two contracts
	ledger *fakestub.Stub                 // the fake ledger that stores the data in memory
	caller []byte                         // the identity (certificate) every transaction is sent as
)

func main() {
	// Optional "-addr" option to change the listen address.
	// Default 127.0.0.1:3000 = the same port as the real connector, and only
	// reachable from this machine.
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	flag.Parse()

	// Build the chaincode from the same two contracts that run on Fabric.
	var err error
	cc, err = contractapi.NewChaincode(&contracts.DeviceContract{}, &contracts.TrustContract{})
	if err != nil {
		log.Fatal(err) // print the error and stop the program
	}

	// Create an empty in-memory ledger for the chaincode named "ztiot".
	ledger = fakestub.New("ztiot", cc)

	// Make a test certificate: MSP "Org1MSP", name "org1admin", OU "admin", no role attribute.
	// The contract's access control reads this certificate, so the mock also
	// tests the real permission checks.
	caller = fakestub.Identity("Org1MSP", "org1admin", "admin", "")

	// ---- Routes (the same paths as gateway/src/server.js) ----

	// Health check. "ledger": "mock" makes it clear this is not real Fabric.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "ledger": "mock"})
	})

	// Write transactions. Each one maps the JSON body to the contract function
	// name and its arguments, in the exact order the contract expects.
	// post() (below) does the shared work: check method, read JSON, invoke, answer.
	http.HandleFunc("/tx/register", post(func(b map[string]interface{}) (string, []string) {
		return "DeviceContract:RegisterDevice", []string{
			str(b["deviceId"]), str(b["deviceType"]), str(b["criticality"]),
			str(b["identityHash"]), str(b["networkAddress"])}
	}))
	http.HandleFunc("/tx/trust", post(func(b map[string]interface{}) (string, []string) {
		return "TrustContract:RecordTrustValue", []string{
			str(b["deviceId"]), str(b["trustValue"]), str(b["threshold"]),
			str(b["attackClass"]), str(b["reasonCode"]), str(b["evidence"]), str(b["confidence"])}
	}))
	http.HandleFunc("/tx/address", post(func(b map[string]interface{}) (string, []string) {
		return "DeviceContract:UpdateDeviceAddress", []string{str(b["deviceId"]), str(b["newAddress"])}
	}))

	// Read-only queries. The value at the end of the URL is the argument,
	http.HandleFunc("/query/device/", query("DeviceContract:GetDevice", "/query/device/"))
	http.HandleFunc("/query/by-address/", query("DeviceContract:GetDeviceByAddress", "/query/by-address/"))
	http.HandleFunc("/query/history/", query("DeviceContract:GetDeviceHistory", "/query/history/"))
	http.HandleFunc("/query/events/", query("DeviceContract:GetTrustEvents", "/query/events/"))

	// port is already used by the real connector), and log.Fatal then stops the program.
	log.Printf("MOCK ledger (in-memory, not Fabric) listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// post builds a handler for a write transaction. "build" turns the JSON body
// into the contract function name and its argument list.
func post(build func(map[string]interface{}) (string, []string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only POST is allowed for transactions (405 = method not allowed).
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "POST only"})
			return
		}
		// Read the JSON body. MaxBytesReader limits it to 64 KB (64<<10 = 65,536 bytes)
		// so a very large request cannot use up memory.
		var body map[string]interface{}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "body must be JSON"})
			return
		}
		// Run the contract function on the in-memory ledger as the admin identity.
		fn, args := build(body)
		resp := ledger.Invoke(cc, caller, fn, args...)
		// If the contract rejected the input (bad value, unknown device, no
		// permission), pass its message back with 400.
		if resp.Status != 200 {
			writeJSON(w, 400, map[string]string{"error": resp.Message})
			return
		}
		// Same answer shape as the real connector: status and transaction ID.
		writeJSON(w, 200, map[string]string{"status": "committed", "txId": ledger.LastTxID})
	}
}

// query builds a handler for a read-only query. fn is the contract function
// and prefix is the part of the URL before the argument.
func query(fn, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// "/query/device/dev-001" minus "/query/device/" = "dev-001"
		arg := strings.TrimPrefix(r.URL.Path, prefix)
		resp := ledger.Invoke(cc, caller, fn, arg)
		if resp.Status != 200 {
			// "not found" type messages become 404, any other contract error 400.
			// The bridge passes 400 and 404 on to its own caller.
			code := 400
			if strings.Contains(resp.Message, "not registered") || strings.Contains(resp.Message, "no device") {
				code = 404
			}
			writeJSON(w, code, map[string]string{"error": resp.Message})
			return
		}
		// The contract already returns JSON, so send it back unchanged.
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp.Payload)
	}
}

// str turns a JSON value into the string form the contract arguments use.
// Fabric passes every contract argument as text, so numbers and booleans
// must be converted first.
func str(v interface{}) string {
	switch t := v.(type) {
	case nil: // field missing in the JSON body -> empty text
		return ""
	case string: // already text
		return t
	case float64: // JSON numbers arrive as float64; 'f', -1 writes 88 as "88" and 72.5 as "72.5"
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	// Anything else (a list or an object) is written back as JSON text.
	b, _ := json.Marshal(v)
	return string(b)
}

// writeJSON sends a JSON answer with the given HTTP status code.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code) // must come after the header is set and before the body
	json.NewEncoder(w).Encode(v)
}
