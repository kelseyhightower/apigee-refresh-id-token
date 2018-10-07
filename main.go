package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	iam "google.golang.org/api/iam/v1"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
)

var (
	organization   string
	environment    string
	keyValueMap    string
	serviceAccount string
	functionUrl    string
)

type KeyValueMapEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ApigeeLoginResponse struct {
	AccessToken string `json:"access_token"`
}

func main() {
	flag.StringVar(&url, "url", "", "Google Cloud Function HTTP URL")
	flag.StringVar(&serviceAccount, "service-account", "", "Service account file")
	flag.Parse()

	if url == "" {
		log.Println("--url is required")
		os.Exit(1)
	}

	if serviceAccount == "" {
		log.Println("--service-account is required")
		os.Exit(1)
	}

	organization := "hightowerlabs"
	environment := "prod"
	mapName := "google-cloud-functions"
	entryName := "token"

	serviceAccountData, err := ioutil.ReadFile(serviceAccount)
	if err != nil {
		log.Fatal(err)
	}

	config, err := google.JWTConfigFromJSON(serviceAccountData, iam.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}

	iamcredentialsService, err := iamcredentials.New(config.Client(oauth2.NoContext))
	if err != nil {
		log.Fatal(err)
	}

	serviceAccountResourceName := fmt.Sprintf("projects/-/serviceAccounts/%s", config.Email)

	idTokenRequest := &iamcredentials.GenerateIdTokenRequest{
		Audience:  url,
		Delegates: []string{serviceAccountResourceName},
	}

	idTokenResponse, err := iamcredentialsService.Projects.ServiceAccounts.GenerateIdToken(
		serviceAccountResourceName, idTokenRequest).Do()
	if err != nil {
		log.Fatal(err)
	}

	// Get Apigee access token
	apigeeLoginRequest, err := http.NewRequest("POST", "https://login.apigee.com/oauth/token", nil)
	if err != nil {
		log.Fatal(err)
	}

	apigeeLoginRequest.Header.Add("Accept", "application/json;charset=utf-8")
	apigeeLoginRequest.Header.Add("Authorization", "Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0")

	apigeeLoginValues := apigeeLoginRequest.URL.Query()
	apigeeLoginValues.Add("username", "apigee@hightowerlabs.org")
	apigeeLoginValues.Add("password", "!Aapig33B0t")
	apigeeLoginValues.Add("grant_type", "password")
	apigeeLoginRequest.URL.RawQuery = apigeeLoginValues.Encode()

	apigeeLoginResponse, err := http.DefaultClient.Do(apigeeLoginRequest)
	if err != nil {
		log.Fatal(err)
	}

	apigeeLoginResponseData, err := ioutil.ReadAll(apigeeLoginResponse.Body)
	if err != nil {
		log.Fatal(err)
	}

	apigeeLoginResponse.Body.Close()

	var a ApigeeLoginResponse

	err = json.Unmarshal(apigeeLoginResponseData, &a)
	if err != nil {
		log.Fatal(err)
	}

	// Update Apigee key value map.
	entry := KeyValueMapEntry{
		Name:  "token",
		Value: idTokenResponse.Token,
	}

	entryData, err := json.Marshal(&entry)
	if err != nil {
		log.Fatal(err)
	}

	url := formatUpdateKeyValueMapsUrl(organization, environment, mapName, entryName)
	apigeeUpdateKeyValueMapRequest, err := http.NewRequest("POST", url, bytes.NewBuffer(entryData))
	if err != nil {
		log.Fatal(err)
	}

	apigeeUpdateKeyValueMapRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.AccessToken))
	apigeeUpdateKeyValueMapRequest.Header.Add("Content-Type", "application/json")

	apigeeUpdateKeyValueMapResponse, err := http.DefaultClient.Do(apigeeUpdateKeyValueMapRequest)
	if err != nil {
		log.Fatal(err)
	}

	if apigeeUpdateKeyValueMapResponse.StatusCode != 200 {
		log.Println(apigeeUpdateKeyValueMapResponse.StatusCode)
	}
}

func formatUpdateKeyValueMapsUrl(organization, environment, mapName, entryName string) string {
	u := "https://api.enterprise.apigee.com/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/%s"
	return fmt.Sprintf(u, organization, environment, mapName, entryName)
}
