// Command mockledger runs the real smart contract in memory behind the same
// HTTP endpoints as the Fabric gateway (gateway/src/server.js).
//
// It is a DEVELOPMENT TOOL ONLY. Use it to build and test the Python bridge,
// the trust generator and the dashboard on a laptop without starting Fabric.
// It is never deployed and never used for reported results.
//
//	go run ./cmd/mockledger            (listens on 127.0.0.1:3000)
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/contracts"
	"github.com/ztiot/ztiot-cc/fakestub"
)

var (
	cc     *contractapi.ContractChaincode
	ledger *fakestub.Stub
	caller []byte
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	flag.Parse()

	var err error
	cc, err = contractapi.NewChaincode(&contracts.DeviceContract{}, &contracts.TrustContract{})
	if err != nil {
		log.Fatal(err)
	}
	ledger = fakestub.New("ztiot", cc)
	// the real gateway connects as the Org1 admin for PP1, so the mock does too
	caller = fakestub.Identity("Org1MSP", "org1admin", "admin", "")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "ledger": "mock"})
	})
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
	http.HandleFunc("/query/device/", query("DeviceContract:GetDevice", "/query/device/"))
	http.HandleFunc("/query/by-address/", query("DeviceContract:GetDeviceByAddress", "/query/by-address/"))
	http.HandleFunc("/query/history/", query("DeviceContract:GetDeviceHistory", "/query/history/"))
	http.HandleFunc("/query/events/", query("DeviceContract:GetTrustEvents", "/query/events/"))

	log.Printf("MOCK ledger (in-memory, not Fabric) listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func post(build func(map[string]interface{}) (string, []string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "POST only"})
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "body must be JSON"})
			return
		}
		fn, args := build(body)
		resp := ledger.Invoke(cc, caller, fn, args...)
		if resp.Status != 200 {
			writeJSON(w, 400, map[string]string{"error": resp.Message})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "committed", "txId": ledger.LastTxID})
	}
}

func query(fn, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		arg := strings.TrimPrefix(r.URL.Path, prefix)
		resp := ledger.Invoke(cc, caller, fn, arg)
		if resp.Status != 200 {
			code := 400
			if strings.Contains(resp.Message, "not registered") || strings.Contains(resp.Message, "no device") {
				code = 404
			}
			writeJSON(w, code, map[string]string{"error": resp.Message})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp.Payload)
	}
}

// str turns a JSON value into the string form the contract arguments use.
func str(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
