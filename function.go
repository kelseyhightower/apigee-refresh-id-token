// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package function

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"cloud.google.com/go/functions/metadata"
	"cloud.google.com/go/logging"
	"cloud.google.com/go/storage"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"go.opencensus.io/trace"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/genproto/googleapis/api/monitoredres"

	iam "google.golang.org/api/iam/v1"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
)

type ApigeeCredentials struct {
	Username string
	Password string
}

type PubSubMessage struct {
	Data []byte `json:"data"`
}

type RefreshTokenEvent struct {
	Environment  string `json:"environment"`
	FunctionUrl  string `json:"function_url"`
	Key          string `json:"key"`
	KeyValueMap  string `json:"key_value_map"`
	Organization string `json:"organization"`
}

type KeyValueMapEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ApigeeLoginResponse struct {
	AccessToken string `json:"access_token"`
}

func F(ctx context.Context, m PubSubMessage) error {
	eventMetadata, ok := metadata.FromContext(ctx)
	if !ok {
		return fmt.Errorf("Failed to extract event metadata from context")
	}

	projectId := os.Getenv("GCP_PROJECT")
	if projectId == "" {
		return fmt.Errorf("Failed to extract GCP project ID from GCP_PROJECT environment variable, empty string")
	}

	functionName := os.Getenv("FUNCTION_NAME")
	if functionName == "" {
		return fmt.Errorf("Failed to extract function name from FUNCTION_NAME environment variable, empty string")
	}

	region := os.Getenv("FUNCTION_REGION")
	if region == "" {
		return fmt.Errorf("Failed to extract function region from FUNCTION_REGION environment variable, empty string")
	}

	// Setup Stackdriver logging.
	//
	// This code assumes the function was invoked by Pub/Sub
	// which sets the event ID to the same value as the function
	// execution ID.
	//
	// When this function is invoked using the Cloud Functions
	// UI the event ID is not guaranteed to match the function
	// execution ID.
	//
	// When the event ID and function ID do not match Stackdriver
	// will not correlate logs emitted by this function with the
	// logs produced by the underlying function runtime.
	loggingClient, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		return fmt.Errorf("Failed to create Stackdriver logging client: %s", err)
	}

	monitoredResource := monitoredres.MonitoredResource{
		Type: "cloud_function",
		Labels: map[string]string{
			"function_name": functionName,
			"project_id":    projectId,
			"region":        region,
		},
	}

	commonLabels := make(map[string]string)
	commonLabels["execution_id"] = eventMetadata.EventID

	logger := loggingClient.Logger("cloudfunctions.googleapis.com/cloud-functions",
		logging.CommonResource(&monitoredResource),
		logging.CommonLabels(commonLabels),
	)

	// Ensure logs are sent to Stackdriver.
	defer logger.Flush()

	serviceAccountEmail := os.Getenv("FUNCTION_IDENTITY")
	if serviceAccountEmail == "" {
		message := "Failed to extract function identity from FUNCTION_IDENTITY environment variable, empty string"
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	apigeeCredentialsBucket := os.Getenv("APIGEE_CREDENTIALS_BUCKET")
	if apigeeCredentialsBucket == "" {
		message := "Failed to extract credentials bucket name from APIGEE_CREDENTIALS_BUCKET environment variable, empty string"
        logger.Log(logging.Entry{
            Payload:  message,
            Severity: logging.Error,
        })
        return fmt.Errorf(message)
	}

	apigeeCredentialsFile := os.Getenv("APIGEE_CREDENTIALS_FILE")
    if apigeeCredentialsFile == "" {
        message := "Failed to extract credentials file name from APIGEE_CREDENTIALS_FILE environment variable, empty string"
        logger.Log(logging.Entry{
            Payload:  message,
            Severity: logging.Error,
        })
        return fmt.Errorf(message)
    }

	// Setup Stackdriver tracing to trace every function invocation.
	stackdriverExporter, err := stackdriver.NewExporter(stackdriver.Options{ProjectID: projectId})
	if err != nil {
		message := fmt.Sprintf("Failed to create Stackdriver trace exporter: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	trace.RegisterExporter(stackdriverExporter)
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	// Start tracing function execution.
	parentSpanContext, parentSpan := trace.StartSpan(ctx, "apigee-refresh-id-token")
	defer parentSpan.End()

	// Extract the refresh token event from the Pub/Sub message.
	//
	// This code assumes the Cloud Pub/Sub message was created by
	// Cloud Scheduler which Base64 encodes payloads before
	// publishing to Cloud Pub/Sub. This results in the message
	// data field being Base64 encoded twice:
	//
	//   {"data": "Base64(Base64(RefreshTokenEvent))"}
	//
	// The Cloud Function Go runtime Base64 decodes the Pub/Sub
	// message data field before invoking the function, which
	// results in the data field holding the Base64 encoded string
	// created by Cloud Scheduler.
	//
	// The message data field must be Base64 decoded before JSON
	// deserialization.
	messageData, err := base64.StdEncoding.DecodeString(string(m.Data))
	if err != nil {
		labels := map[string]string{
			"data": string(m.Data),
		}
		message := fmt.Sprintf("Failed to Base64 decode message data: %s", err)
		logger.Log(logging.Entry{
			Labels:   labels,
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	var event RefreshTokenEvent
	if err := json.Unmarshal(messageData, &event); err != nil {
		labels := map[string]string{
			"base64_decoded_message_data": string(messageData),
		}
		message := fmt.Sprintf("Failed to unmarshal message data: %s", err)
		logger.Log(logging.Entry{
			Labels:   labels,
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	// Extract event parameters and set them as Stackdriver common
	// logging labels, which will be attached to all Stackdriver log
	// entries from this point on.
	commonLabels["apigee_environment"] = event.Environment
	commonLabels["apigee_organization"] = event.Organization
	commonLabels["apigee_key_value_map"] = event.KeyValueMap
	commonLabels["apigee_key"] = event.Key
	commonLabels["apigee_function_url"] = event.FunctionUrl

	// Apigee credentials are required to fetch access tokens from
	// the Apigee login service.
	//    https://docs.apigee.com/api-platform/system-administration/using-oauth2
	//
	// Fetch the Apigee credentials from GCS bucket.
	storageClient, err := storage.NewClient(context.Background())
	if err != nil {
		message := fmt.Sprintf("Failed to create storage client: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	o, err := storageClient.Bucket(apigeeCredentialsBucket).Object(apigeeCredentialsFile).NewReader(context.Background())
	if err != nil {
		labels := map[string]string{
            "apigee_credentials_bucket": apigeeCredentialsBucket,
            "apigee_credentials_file":   apigeeCredentialsFile,
        }
		message := fmt.Sprintf("Failed to retrieve Apigee credentials from GCS: %s", err)
		logger.Log(logging.Entry{
			Labels:   labels,
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	var apigeeCredentials ApigeeCredentials
	if err := json.NewDecoder(o).Decode(&apigeeCredentials); err != nil {
		labels := map[string]string{
			"apigee_credentials_bucket": apigeeCredentialsBucket,
			"apigee_credentials_file":   apigeeCredentialsFile,
		}
		message := fmt.Sprintf("Failed to unmarshal Apigee credentials: %s", err)
		logger.Log(logging.Entry{
			Labels:   labels,
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	// Generate an ID token.
	//
	// The ID token is used to invoke private cloud functions.
	iamClient, err := google.DefaultClient(oauth2.NoContext, iam.CloudPlatformScope)
	if err != nil {
		message := fmt.Sprintf("Failed to create IAM google default client: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	iamcredentialsService, err := iamcredentials.New(iamClient)
	if err != nil {
		message := fmt.Sprintf("Failed to create IAM credentials service: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	serviceAccountResourceName := fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountEmail)

	idTokenRequest := &iamcredentials.GenerateIdTokenRequest{
		Audience:  event.FunctionUrl,
		Delegates: []string{serviceAccountResourceName},
	}

	_, generateIdTokenSpan := trace.StartSpan(parentSpanContext, "iam-generate-id-token")

	idTokenResponse, err := iamcredentialsService.Projects.ServiceAccounts.GenerateIdToken(
		serviceAccountResourceName, idTokenRequest).Do()
	if err != nil {
		generateIdTokenSpan.End()

		labels := map[string]string{
			"service_account_resource_name": serviceAccountResourceName,
			"id_token_audience":             event.FunctionUrl,
			"id_token_delegates":            serviceAccountResourceName,
		}
		message := fmt.Sprintf("Failed to generate ID token: %s", err)
		logger.Log(logging.Entry{
			Labels:   labels,
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}
	generateIdTokenSpan.End()

	// Get Apigee access token
	apigeeLoginRequest, err := http.NewRequest("POST", "https://login.apigee.com/oauth/token", nil)
	if err != nil {
		message := fmt.Sprintf("Failed to create Apigee OAuth token request: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	apigeeLoginRequest.Header.Add("Accept", "application/json;charset=utf-8")

	// The Authorization header used for issuing OAuth token requests
	// is a hardcoded value as described in the official docs:
	//
	//  https://docs.apigee.com/api-platform/system-administration/management-api-tokens
	//
	apigeeLoginRequest.Header.Add("Authorization", "Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0")

	apigeeLoginValues := apigeeLoginRequest.URL.Query()
	apigeeLoginValues.Add("username", apigeeCredentials.Username)
	apigeeLoginValues.Add("password", apigeeCredentials.Password)
	apigeeLoginValues.Add("grant_type", "password")
	apigeeLoginRequest.URL.RawQuery = apigeeLoginValues.Encode()

	_, apigeeLoginSpan := trace.StartSpan(parentSpanContext, "apigee-login")

	apigeeLoginResponse, err := http.DefaultClient.Do(apigeeLoginRequest)
	if err != nil {
		apigeeLoginSpan.End()

		message := fmt.Sprintf("Failed to obtain an Apigee OAuth token: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}
	apigeeLoginSpan.End()

	apigeeLoginResponseData, err := ioutil.ReadAll(apigeeLoginResponse.Body)
	if err != nil {
		message := fmt.Sprintf("Failed to read Apigee OAuth token response body: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	apigeeLoginResponse.Body.Close()

	var a ApigeeLoginResponse
	if err := json.Unmarshal(apigeeLoginResponseData, &a); err != nil {
		message := fmt.Sprintf("Failed to unmarshal Apigee OAuth token response body: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	// Refresh the ID token stored in Apigee.
	//
	// This code assumes the Apigee key value map and initial key
	// already exist. The value can be set to any value and will be
	// updated by this function.
	entry := KeyValueMapEntry{
		Name:  event.Key,
		Value: idTokenResponse.Token,
	}

	entryData, err := json.Marshal(&entry)
	if err != nil {
		message := fmt.Sprintf("Failed to marshal Apigee key value map entry: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	url := formatUpdateKeyValueMapsUrl(event.Organization, event.Environment, event.KeyValueMap, event.Key)
	apigeeUpdateKeyValueMapRequest, err := http.NewRequest("POST", url, bytes.NewBuffer(entryData))
	if err != nil {
		message := fmt.Sprintf("Failed to create Apigee key value map request: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	apigeeUpdateKeyValueMapRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.AccessToken))
	apigeeUpdateKeyValueMapRequest.Header.Add("Content-Type", "application/json")

	_, apigeeUpdateKeyValueMapSpan := trace.StartSpan(parentSpanContext, "apigee-update-kvm")

	apigeeUpdateKeyValueMapResponse, err := http.DefaultClient.Do(apigeeUpdateKeyValueMapRequest)
	if err != nil {
		apigeeUpdateKeyValueMapSpan.End()

		message := fmt.Sprintf("Failed to update Apigee key value map: %s", err)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	apigeeUpdateKeyValueMapSpan.End()

	statusCode := apigeeUpdateKeyValueMapResponse.StatusCode
	if statusCode != 200 {
		message := fmt.Sprintf("Failed to update Apigee key value map, status code: %v", statusCode)
		logger.Log(logging.Entry{
			Payload:  message,
			Severity: logging.Error,
		})
		return fmt.Errorf(message)
	}

	logger.Log(logging.Entry{
		Payload:  "Successfully updated Apigee key value map entry",
		Severity: logging.Info,
	})

	return nil
}

func formatUpdateKeyValueMapsUrl(organization, environment, keyValueMap, key string) string {
	u := "https://api.enterprise.apigee.com/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/%s"
	return fmt.Sprintf(u, organization, environment, keyValueMap, key)
}
