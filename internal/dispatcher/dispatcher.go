package dispatcher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/divmora/authpin/internal/model"
)

var (
	ErrUnsupportedChannel = errors.New("unsupported delivery channel")
	ErrDeliveryFailed     = errors.New("delivery failed")
)

// DispatchRequest carries details for sending an OTP to an end recipient.
type DispatchRequest struct {
	Target     string
	Channel    model.Channel
	OTP        string
	Purpose    string
	SenderName string
	TTLMinutes int
	Metadata   map[string]string
}

// Dispatcher is the interface for delivering OTP messages.
type Dispatcher interface {
	Dispatch(ctx context.Context, req *DispatchRequest) error
	Channel() model.Channel
}

// Router dispatches requests to the appropriate channel handler.
type Router struct {
	dispatchers map[model.Channel]Dispatcher
}

// NewRouter constructs a router with registered dispatchers.
func NewRouter(dispatchers ...Dispatcher) *Router {
	r := &Router{
		dispatchers: make(map[model.Channel]Dispatcher),
	}
	for _, d := range dispatchers {
		r.dispatchers[d.Channel()] = d
	}
	return r
}

// Dispatch routes the delivery to the matching channel dispatcher.
func (r *Router) Dispatch(ctx context.Context, req *DispatchRequest) error {
	d, ok := r.dispatchers[req.Channel]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedChannel, req.Channel)
	}
	return d.Dispatch(ctx, req)
}

// --- SMTP Email Dispatcher ---

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	UseTLS   bool
}

type SMTPDispatcher struct {
	cfg SMTPConfig
}

func NewSMTPDispatcher(cfg SMTPConfig) *SMTPDispatcher {
	if cfg.FromName == "" {
		cfg.FromName = "Verification Service"
	}
	return &SMTPDispatcher{cfg: cfg}
}

func (s *SMTPDispatcher) Channel() model.Channel {
	return model.ChannelEmail
}

func (s *SMTPDispatcher) Dispatch(ctx context.Context, req *DispatchRequest) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	subject := fmt.Sprintf("Your %s verification code is %s", req.SenderName, req.OTP)
	if req.SenderName == "" {
		req.SenderName = s.cfg.FromName
	}

	body := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n"+
		"<div style=\"font-family:sans-serif;max-width:500px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:8px;\">"+
		"<h2 style=\"color:#0f172a;margin-top:0;\">%s Verification</h2>"+
		"<p style=\"color:#475569;\">Use the following one-time code to complete your %s verification. This code expires in %d minutes.</p>"+
		"<div style=\"font-size:32px;font-weight:bold;letter-spacing:6px;color:#2563eb;padding:16px 0;\">%s</div>"+
		"<p style=\"color:#94a3b8;font-size:12px;\">If you did not request this code, you can safely ignore this email.</p>"+
		"</div>\r\n",
		s.cfg.FromName, s.cfg.From, req.Target, subject, req.SenderName, req.Purpose, req.TTLMinutes, req.OTP)

	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)

	// Direct delivery with timeout support
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}

	dialer := &net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}

	if s.cfg.UseTLS || s.cfg.Port == 465 {
		tlsConfig := &tls.Config{ServerName: s.cfg.Host}
		conn = tls.Client(conn, tlsConfig)
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client error: %w", err)
	}
	defer client.Quit()

	if s.cfg.Username != "" {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}

	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(req.Target); err != nil {
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte(body)); err != nil {
		return fmt.Errorf("smtp body write failed: %w", err)
	}

	return nil
}

// --- Twilio SMS Dispatcher ---

type TwilioConfig struct {
	AccountSID string
	AuthToken  string
	FromPhone  string
}

type TwilioDispatcher struct {
	cfg    TwilioConfig
	client *http.Client
}

func NewTwilioDispatcher(cfg TwilioConfig) *TwilioDispatcher {
	return &TwilioDispatcher{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *TwilioDispatcher) Channel() model.Channel {
	return model.ChannelSMS
}

func (t *TwilioDispatcher) Dispatch(ctx context.Context, req *DispatchRequest) error {
	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.cfg.AccountSID)

	messageText := fmt.Sprintf("Your verification code is %s. Valid for %d minutes.", req.OTP, req.TTLMinutes)
	data := url.Values{}
	data.Set("To", req.Target)
	data.Set("From", t.cfg.FromPhone)
	data.Set("Body", messageText)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to build twilio request: %w", err)
	}

	httpReq.SetBasicAuth(t.cfg.AccountSID, t.cfg.AuthToken)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("twilio dispatch error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("twilio responded with status: %d", resp.StatusCode)
	}

	return nil
}

// --- In-Memory Mock Dispatcher (for tests and local dev) ---

type MockDispatcher struct {
	mu           sync.Mutex
	channel      model.Channel
	SentMessages []DispatchRequest
}

func NewMockDispatcher(ch model.Channel) *MockDispatcher {
	return &MockDispatcher{
		channel:      ch,
		SentMessages: make([]DispatchRequest, 0),
	}
}

func (m *MockDispatcher) Channel() model.Channel {
	return m.channel
}

func (m *MockDispatcher) Dispatch(ctx context.Context, req *DispatchRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SentMessages = append(m.SentMessages, *req)
	return nil
}

func (m *MockDispatcher) LastSent() *DispatchRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.SentMessages) == 0 {
		return nil
	}
	last := m.SentMessages[len(m.SentMessages)-1]
	return &last
}
