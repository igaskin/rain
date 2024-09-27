package sts

import (
	"context"

	"github.com/aws-cloudformation/rain/internal/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func getClient() *sts.Client {
	return sts.NewFromConfig(aws.Config())
}

// GetSessionToken returns a session token for the current IAM principle
func GetSessionToken() (*types.Credentials, error) {
	res, err := getClient().GetSessionToken(context.Background(), &sts.GetSessionTokenInput{})
	if err != nil {
		return nil, err
	}

	return res.Credentials, nil
}

// GetCallerID returns the identity of the current IAM principal
func GetCallerID() (sts.GetCallerIdentityOutput, error) {
	res, err := getClient().GetCallerIdentity(context.Background(), nil)
	if err != nil {
		return sts.GetCallerIdentityOutput{}, err
	}

	return *res, nil
}

// GetAccountID gets the account number of the current AWS account
func GetAccountID() (string, error) {
	id, err := GetCallerID()
	if err != nil {
		return "", err
	}

	return *id.Account, nil
}

// AssumeRole assumes a role and returns temporary security credentials
func AssumeRole(roleArn string, roleSessionName string, durationSeconds int32) (*types.Credentials, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &roleSessionName,
		DurationSeconds: &durationSeconds,
	}

	res, err := getClient().AssumeRole(context.Background(), input)
	if err != nil {
		return nil, err
	}

	return res.Credentials, nil
}
