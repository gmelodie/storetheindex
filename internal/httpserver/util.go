// Package httpserver provides functionality common to all storetheindex HTTP
// servers
package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	v0 "github.com/filecoin-project/storetheindex/api/v0"
	logging "github.com/ipfs/go-log/v2"
)

var log = logging.Logger("indexer/http")

func WriteJsonResponse(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		log.Errorw("cannot write response", "err", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func HandleError(w http.ResponseWriter, err error, reqType string) {
	status := http.StatusBadRequest
	var apierr *v0.Error
	if errors.As(err, &apierr) {
		if apierr.Status() >= 500 {
			msg := fmt.Sprintf("Cannot handle %s request", strings.ToUpper(reqType))
			log.Errorw(msg, "err", apierr.Error(), "status", apierr.Status())
			http.Error(w, "", apierr.Status())
			return
		}
		status = apierr.Status()
	}
	msg := fmt.Sprintf("Bad %s request", strings.ToUpper(reqType))
	log.Infow(msg, "err", err, "status", status)
	http.Error(w, err.Error(), status)
}
