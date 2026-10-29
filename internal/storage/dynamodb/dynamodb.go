package dynamodb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/storage"
)

// Engine is the AWS DynamoDB implementation of storage.StorageEngine.
type Engine struct {
	client    *dynamodb.Client
	tableName string
}

// Config specifies connection properties for DynamoDB.
type Config struct {
	Region    string
	TableName string
	Endpoint  string // Custom endpoint for LocalStack or DynamoDB Local
}

// New creates a new AWS DynamoDB storage engine.
func New(ctx context.Context, cfg Config) (*Engine, error) {
	if cfg.TableName == "" {
		cfg.TableName = "authpin_sessions"
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	optFns := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config for dynamodb: %w", err)
	}

	client := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = &cfg.Endpoint
		}
	})

	return &Engine{
		client:    client,
		tableName: cfg.TableName,
	}, nil
}

func (e *Engine) SaveSession(ctx context.Context, session *model.OTPSession) error {
	ttlEpoch := session.ExpiresAt.Unix()

	item := map[string]types.AttributeValue{
		"token_hash":            &types.AttributeValueMemberS{Value: session.TokenHash},
		"id":                    &types.AttributeValueMemberS{Value: session.ID},
		"project_id":            &types.AttributeValueMemberS{Value: session.ProjectID},
		"otp_hash":              &types.AttributeValueMemberS{Value: session.OTPHash},
		"recipient_encrypted":   &types.AttributeValueMemberS{Value: base64.StdEncoding.EncodeToString(session.RecipientEncrypted)},
		"recipient_lookup_hash": &types.AttributeValueMemberS{Value: session.RecipientLookupHash},
		"channel":               &types.AttributeValueMemberS{Value: string(session.Channel)},
		"otp_type":              &types.AttributeValueMemberS{Value: string(session.OTPType)},
		"otp_length":            &types.AttributeValueMemberN{Value: strconv.Itoa(session.OTPLength)},
		"purpose":               &types.AttributeValueMemberS{Value: session.Purpose},
		"attempts":              &types.AttributeValueMemberN{Value: strconv.Itoa(session.Attempts)},
		"max_attempts":          &types.AttributeValueMemberN{Value: strconv.Itoa(session.MaxAttempts)},
		"status":                &types.AttributeValueMemberS{Value: string(session.Status)},
		"created_at":            &types.AttributeValueMemberS{Value: session.CreatedAt.Format(time.RFC3339Nano)},
		"expires_at":            &types.AttributeValueMemberS{Value: session.ExpiresAt.Format(time.RFC3339Nano)},
		"ttl":                   &types.AttributeValueMemberN{Value: strconv.FormatInt(ttlEpoch, 10)},
	}

	if len(session.MetadataEncrypted) > 0 {
		item["metadata_encrypted"] = &types.AttributeValueMemberS{Value: base64.StdEncoding.EncodeToString(session.MetadataEncrypted)}
	}

	input := &dynamodb.PutItemInput{
		TableName: &e.tableName,
		Item:      item,
	}

	if _, err := e.client.PutItem(ctx, input); err != nil {
		return fmt.Errorf("dynamodb PutItem error: %w", err)
	}
	return nil
}

func (e *Engine) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.OTPSession, error) {
	input := &dynamodb.GetItemInput{
		TableName: &e.tableName,
		Key: map[string]types.AttributeValue{
			"token_hash": &types.AttributeValueMemberS{Value: tokenHash},
		},
		ConsistentRead: boolPtr(true),
	}

	out, err := e.client.GetItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetItem error: %w", err)
	}

	if len(out.Item) == 0 {
		return nil, storage.ErrSessionNotFound
	}

	sess := &model.OTPSession{
		TokenHash: tokenHash,
	}

	if v, ok := out.Item["id"].(*types.AttributeValueMemberS); ok {
		sess.ID = v.Value
	}
	if v, ok := out.Item["project_id"].(*types.AttributeValueMemberS); ok {
		sess.ProjectID = v.Value
	}
	if v, ok := out.Item["otp_hash"].(*types.AttributeValueMemberS); ok {
		sess.OTPHash = v.Value
	}
	if v, ok := out.Item["recipient_encrypted"].(*types.AttributeValueMemberS); ok {
		sess.RecipientEncrypted, _ = base64.StdEncoding.DecodeString(v.Value)
	}
	if v, ok := out.Item["recipient_lookup_hash"].(*types.AttributeValueMemberS); ok {
		sess.RecipientLookupHash = v.Value
	}
	if v, ok := out.Item["channel"].(*types.AttributeValueMemberS); ok {
		sess.Channel = model.Channel(v.Value)
	}
	if v, ok := out.Item["otp_type"].(*types.AttributeValueMemberS); ok {
		sess.OTPType = model.OTPType(v.Value)
	}
	if v, ok := out.Item["otp_length"].(*types.AttributeValueMemberN); ok {
		sess.OTPLength, _ = strconv.Atoi(v.Value)
	}
	if v, ok := out.Item["purpose"].(*types.AttributeValueMemberS); ok {
		sess.Purpose = v.Value
	}
	if v, ok := out.Item["attempts"].(*types.AttributeValueMemberN); ok {
		sess.Attempts, _ = strconv.Atoi(v.Value)
	}
	if v, ok := out.Item["max_attempts"].(*types.AttributeValueMemberN); ok {
		sess.MaxAttempts, _ = strconv.Atoi(v.Value)
	}
	if v, ok := out.Item["status"].(*types.AttributeValueMemberS); ok {
		sess.Status = model.Status(v.Value)
	}
	if v, ok := out.Item["metadata_encrypted"].(*types.AttributeValueMemberS); ok {
		sess.MetadataEncrypted, _ = base64.StdEncoding.DecodeString(v.Value)
	}
	if v, ok := out.Item["created_at"].(*types.AttributeValueMemberS); ok {
		sess.CreatedAt, _ = time.Parse(time.RFC3339Nano, v.Value)
	}
	if v, ok := out.Item["expires_at"].(*types.AttributeValueMemberS); ok {
		sess.ExpiresAt, _ = time.Parse(time.RFC3339Nano, v.Value)
	}
	if v, ok := out.Item["verified_at"].(*types.AttributeValueMemberS); ok {
		t, _ := time.Parse(time.RFC3339Nano, v.Value)
		sess.VerifiedAt = &t
	}

	return sess, nil
}

func (e *Engine) IncrementAttempts(ctx context.Context, tokenHash string) (int, error) {
	expr := "ADD attempts :inc"
	cond := "attribute_exists(token_hash)"

	input := &dynamodb.UpdateItemInput{
		TableName: &e.tableName,
		Key: map[string]types.AttributeValue{
			"token_hash": &types.AttributeValueMemberS{Value: tokenHash},
		},
		UpdateExpression:    &expr,
		ConditionExpression: &cond,
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inc": &types.AttributeValueMemberN{Value: "1"},
		},
		ReturnValues: types.ReturnValueUpdatedNew,
	}

	out, err := e.client.UpdateItem(ctx, input)
	if err != nil {
		var condFailed *types.ConditionalCheckFailedException
		if errors.As(err, &condFailed) {
			return 0, storage.ErrSessionNotFound
		}
		return 0, fmt.Errorf("dynamodb UpdateItem error: %w", err)
	}

	if attemptsVal, ok := out.Attributes["attempts"].(*types.AttributeValueMemberN); ok {
		newAttempts, _ := strconv.Atoi(attemptsVal.Value)
		return newAttempts, nil
	}

	return 0, nil
}

func (e *Engine) MarkVerified(ctx context.Context, tokenHash string, verifiedAt time.Time) error {
	expr := "SET #s = :verified, verified_at = :now"
	cond := "#s = :pending"

	input := &dynamodb.UpdateItemInput{
		TableName: &e.tableName,
		Key: map[string]types.AttributeValue{
			"token_hash": &types.AttributeValueMemberS{Value: tokenHash},
		},
		UpdateExpression:    &expr,
		ConditionExpression: &cond,
		ExpressionAttributeNames: map[string]string{
			"#s": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":verified": &types.AttributeValueMemberS{Value: string(model.StatusVerified)},
			":pending":  &types.AttributeValueMemberS{Value: string(model.StatusPending)},
			":now":      &types.AttributeValueMemberS{Value: verifiedAt.Format(time.RFC3339Nano)},
		},
	}

	_, err := e.client.UpdateItem(ctx, input)
	if err != nil {
		var condFailed *types.ConditionalCheckFailedException
		if errors.As(err, &condFailed) {
			return storage.ErrSessionNotFound
		}
		return fmt.Errorf("failed to mark session verified in dynamodb: %w", err)
	}
	return nil
}

func (e *Engine) Invalidate(ctx context.Context, tokenHash string, status model.Status) error {
	expr := "SET #s = :status"
	cond := "attribute_exists(token_hash)"

	input := &dynamodb.UpdateItemInput{
		TableName: &e.tableName,
		Key: map[string]types.AttributeValue{
			"token_hash": &types.AttributeValueMemberS{Value: tokenHash},
		},
		UpdateExpression:    &expr,
		ConditionExpression: &cond,
		ExpressionAttributeNames: map[string]string{
			"#s": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: string(status)},
		},
	}

	_, err := e.client.UpdateItem(ctx, input)
	if err != nil {
		var condFailed *types.ConditionalCheckFailedException
		if errors.As(err, &condFailed) {
			return storage.ErrSessionNotFound
		}
		return fmt.Errorf("failed to invalidate dynamodb session: %w", err)
	}
	return nil
}

// CleanupExpired is a no-op for DynamoDB because AWS DynamoDB natively purges expired items automatically via the `ttl` attribute!
func (e *Engine) CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	// Native DynamoDB TTL handles item deletion in the cloud with zero consumed read/write capacity!
	return 0, nil
}

func (e *Engine) Ping(ctx context.Context) error {
	_, err := e.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: &e.tableName,
	})
	return err
}

func (e *Engine) Close() error {
	return nil
}

func boolPtr(b bool) *bool {
	return &b
}
