module github.com/kelseyhightower/apigee-refresh-id-token

require (
	cloud.google.com/go v0.26.0
	cloud.google.com/go/functions/metadata v0.0.0
	contrib.go.opencensus.io/exporter/stackdriver v0.6.0
	github.com/aws/aws-sdk-go v1.15.49 // indirect
	github.com/googleapis/gax-go v2.0.0+incompatible // indirect
	go.opencensus.io v0.17.0
	golang.org/x/net v0.0.0-20180911220305-26e67e76b6c3 // indirect
	golang.org/x/oauth2 v0.0.0-20180821212333-d2e6202438be
	google.golang.org/api v0.0.0-20180916000451-19ff8768a5c0
	google.golang.org/genproto v0.0.0-20181004005441-af9cb2a35e7f
	google.golang.org/grpc v1.15.0 // indirect
)

replace cloud.google.com/go/functions/metadata => ./metadata
