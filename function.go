package function

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
		return errors.New("GCP_PROJECT must be set and non-empty")
	}

	functionName := os.Getenv("FUNCTION_NAME")
	if functionName == "" {
		return errors.New("FUNCTION_NAME must be set and non-empty")
	}

	region := os.Getenv("FUNCTION_REGION")
	if region == "" {
		return errors.New("FUNCTION_REGION must be set and non-empty")
	}

	// Setup Stackdriver logging.
	loggingClient, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		return fmt.Errorf("error setting up Stackdriver logging: %s", err)
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

	defer logger.Flush()

	serviceAccountEmail := os.Getenv("FUNCTION_IDENTITY")
	if serviceAccountEmail == "" {
		logger.Log(logging.Entry{
			Payload:  "FUNCTION_IDENTITY must be set and non-empty",
			Severity: logging.Error,
		})
		return errors.New("FUNCTION_IDENTITY must be set and non-empty")
	}

	// Setup Stackdriver tracing.
	stackdriverExporter, err := stackdriver.NewExporter(stackdriver.Options{ProjectID: projectId})
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error creating stackdriver exporter: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	trace.RegisterExporter(stackdriverExporter)
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	parentSpanContext, parentSpan := trace.StartSpan(ctx, "apigee-refresh-id-token")
	defer parentSpan.End()

	// Process refresh token event.
	eventLabels := make(map[string]string)
	eventLabels["data"] = string(m.Data)
	d, err := base64.StdEncoding.DecodeString(string(m.Data))
	if err != nil {
		logger.Log(logging.Entry{
			Labels:   eventLabels,
			Payload:  fmt.Sprintf("error base64 decoding refresh token event: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	var event RefreshTokenEvent
	if err := json.Unmarshal(d, &event); err != nil {
		logger.Log(logging.Entry{
			Labels:   eventLabels,
			Payload:  fmt.Sprintf("error parsing refresh token event: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	commonLabels["apigee_environment"] = event.Environment
	commonLabels["apigee_organization"] = event.Organization
	commonLabels["apigee_key_value_map"] = event.KeyValueMap
	commonLabels["apigee_key"] = event.Key
	commonLabels["apigee_function_url"] = event.FunctionUrl

	// Get Apigee credentials from GCS bucket.
	storageClient, err := storage.NewClient(context.Background())
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error creating storage client: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	o, err := storageClient.Bucket("hightowerlabs").Object("apigee-credentials.json").NewReader(context.Background())
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error loading Apigee credentials: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	var apigeeCredentials ApigeeCredentials
	if err := json.NewDecoder(o).Decode(&apigeeCredentials); err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error loading Apigee credentials: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	client, err := google.DefaultClient(oauth2.NoContext, iam.CloudPlatformScope)
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error setting up google default client: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	iamcredentialsService, err := iamcredentials.New(client)
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error creating IAM credentials service: %s", err),
			Severity: logging.Error,
		})
		return err
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
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error generating ID token: %s", err),
			Severity: logging.Error,
		})
		return err
	}
	generateIdTokenSpan.End()

	// Get Apigee access token
	apigeeLoginRequest, err := http.NewRequest("POST", "https://login.apigee.com/oauth/token", nil)
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error creating Apigee oauth token request: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	apigeeLoginRequest.Header.Add("Accept", "application/json;charset=utf-8")
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
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error obtaining Apigee oauth token: %s", err),
			Severity: logging.Error,
		})
		return err
	}
	apigeeLoginSpan.End()

	apigeeLoginResponseData, err := ioutil.ReadAll(apigeeLoginResponse.Body)
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error reading Apigee oauth token request: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	apigeeLoginResponse.Body.Close()

	var a ApigeeLoginResponse

	err = json.Unmarshal(apigeeLoginResponseData, &a)
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error unmarshalling Apigee oauth token request: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	// Update Apigee key value map.
	entry := KeyValueMapEntry{
		Name:  event.Key,
		Value: idTokenResponse.Token,
	}

	entryData, err := json.Marshal(&entry)
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error marshalling Apigee key value map entry: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	url := formatUpdateKeyValueMapsUrl(event.Organization, event.Environment, event.KeyValueMap, event.Key)
	apigeeUpdateKeyValueMapRequest, err := http.NewRequest("POST", url, bytes.NewBuffer(entryData))
	if err != nil {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error creating Apigee update key value map request: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	apigeeUpdateKeyValueMapRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.AccessToken))
	apigeeUpdateKeyValueMapRequest.Header.Add("Content-Type", "application/json")

	_, apigeeUpdateKeyValueMapSpan := trace.StartSpan(parentSpanContext, "apigee-update-kvm")
	apigeeUpdateKeyValueMapResponse, err := http.DefaultClient.Do(apigeeUpdateKeyValueMapRequest)
	if err != nil {
		apigeeUpdateKeyValueMapSpan.End()
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error during Apigee update key value map request: %s", err),
			Severity: logging.Error,
		})
		return err
	}

	apigeeUpdateKeyValueMapSpan.End()

	statusCode := apigeeUpdateKeyValueMapResponse.StatusCode
	if statusCode != 200 {
		logger.Log(logging.Entry{
			Payload:  fmt.Sprintf("error updating Apigee key value map got status code %s", statusCode),
			Severity: logging.Error,
		})
	}

	logger.Log(logging.Entry{
		Payload:  "successfully updated key value map entry",
		Severity: logging.Info,
	})

	return nil
}

func formatUpdateKeyValueMapsUrl(organization, environment, keyValueMap, key string) string {
	u := "https://api.enterprise.apigee.com/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/%s"
	return fmt.Sprintf(u, organization, environment, keyValueMap, key)
}
