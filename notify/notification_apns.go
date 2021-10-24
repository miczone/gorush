package notify

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/miczone/gorush/config"
	"github.com/miczone/gorush/core"
	"github.com/miczone/gorush/logx"
	"github.com/miczone/gorush/status"

	"github.com/mitchellh/mapstructure"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

var (
	idleConnTimeout = 90 * time.Second
	tlsDialTimeout  = 20 * time.Second
	tcpKeepAlive    = 60 * time.Second
)

var doOnce sync.Once

// DialTLS is the default dial function for creating TLS connections for
// non-proxied HTTPS requests.
var DialTLS = func(cfg *tls.Config) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   tlsDialTimeout,
			KeepAlive: tcpKeepAlive,
		}
		return tls.DialWithDialer(dialer, network, addr, cfg)
	}
}

// Sound sets the aps sound on the payload.
type Sound struct {
	Critical int     `json:"critical,omitempty"`
	Name     string  `json:"name,omitempty"`
	Volume   float32 `json:"volume,omitempty"`
}

// InitAPNSClient use for initialize APNs Client.
func InitAPNSClient(cfg config.ConfYaml, key_path string, key_base64 string, key_type string, password string, key_id string, team_id string) (*apns2.Client, error) {
	if cfg.Ios.Enabled {
		var err error
		var authKey *ecdsa.PrivateKey
		var certificateKey tls.Certificate
		var ext string

		var key_file_path = key_path
		if key_file_path == "" {
			key_file_path = cfg.Ios.KeyPath
		}

		var key_base64_string = key_base64
		if key_base64_string == "" {
			key_base64_string = cfg.Ios.KeyBase64
		}

		var key_password = password
		if key_password == "" {
			key_password = cfg.Ios.Password
		}

		var key_type_string = key_type
		if key_type_string == "" {
			key_type_string = cfg.Ios.KeyType
		}

		var key_id_string = key_id
		if key_id_string == "" {
			key_id_string = cfg.Ios.KeyID
		}

		var team_id_string = team_id
		if team_id_string == "" {
			team_id_string = cfg.Ios.TeamID
		}

		if key_file_path != "" {
			ext = filepath.Ext(key_file_path)

			switch ext {
			case ".p12":
				certificateKey, err = certificate.FromP12File(key_file_path, key_password)
			case ".pem":
				certificateKey, err = certificate.FromPemFile(key_file_path, key_password)
			case ".p8":
				authKey, err = token.AuthKeyFromFile(key_file_path)
			default:
				err = errors.New("wrong certificate key extension")
			}

			if err != nil {
				logx.LogError.Error("Cert Error:", err.Error())

				return nil, err
			}
		} else if key_base64_string != "" {
			ext = "." + key_type_string
			key, err := base64.StdEncoding.DecodeString(key_base64_string)
			if err != nil {
				logx.LogError.Error("base64 decode error:", err.Error())

				return nil, err
			}
			switch ext {
			case ".p12":
				certificateKey, err = certificate.FromP12Bytes(key, key_password)
			case ".pem":
				certificateKey, err = certificate.FromPemBytes(key, key_password)
			case ".p8":
				authKey, err = token.AuthKeyFromBytes(key)
			default:
				err = errors.New("wrong certificate key type")
			}

			if err != nil {
				logx.LogError.Error("Cert Error:", err.Error())

				return nil, err
			}
		}

		if ext == ".p8" {
			if key_id_string == "" || team_id_string == "" {
				msg := "You should provide ios.KeyID and ios.TeamID for P8 token"
				logx.LogError.Error(msg)
				return nil, errors.New(msg)
			}
			token := &token.Token{
				AuthKey: authKey,
				// KeyID from developer account (Certificates, Identifiers & Profiles -> Keys)
				KeyID: key_id_string,
				// TeamID from developer account (View Account -> Membership)
				TeamID: team_id_string,
			}

			ApnsClient, err = newApnsTokenClient(cfg, token)
		} else {
			ApnsClient, err = newApnsClient(cfg, certificateKey)
		}

		if h2Transport, ok := ApnsClient.HTTPClient.Transport.(*http2.Transport); ok {
			configureHTTP2ConnHealthCheck(h2Transport)
		}

		if err != nil {
			logx.LogError.Error("Transport Error:", err.Error())

			return nil, err
		}

		doOnce.Do(func() {
			MaxConcurrentIOSPushes = make(chan struct{}, cfg.Ios.MaxConcurrentPushes)
		})
	}

	return ApnsClient, nil
}

func newApnsClient(cfg config.ConfYaml, certificate tls.Certificate) (*apns2.Client, error) {
	var client *apns2.Client

	if cfg.Ios.Production {
		client = apns2.NewClient(certificate).Production()
	} else {
		client = apns2.NewClient(certificate).Development()
	}

	if cfg.Core.HTTPProxy == "" {
		return client, nil
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	if len(certificate.Certificate) > 0 {
		tlsConfig.BuildNameToCertificate()
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS:         DialTLS(tlsConfig),
		Proxy:           http.DefaultTransport.(*http.Transport).Proxy,
		IdleConnTimeout: idleConnTimeout,
	}

	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	configureHTTP2ConnHealthCheck(h2Transport)

	client.HTTPClient.Transport = transport

	return client, nil
}

func newApnsTokenClient(cfg config.ConfYaml, token *token.Token) (*apns2.Client, error) {
	var client *apns2.Client

	if cfg.Ios.Production {
		client = apns2.NewTokenClient(token).Production()
	} else {
		client = apns2.NewTokenClient(token).Development()
	}

	if cfg.Core.HTTPProxy == "" {
		return client, nil
	}

	transport := &http.Transport{
		DialTLS:         DialTLS(nil),
		Proxy:           http.DefaultTransport.(*http.Transport).Proxy,
		IdleConnTimeout: idleConnTimeout,
	}

	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	configureHTTP2ConnHealthCheck(h2Transport)

	client.HTTPClient.Transport = transport

	return client, nil
}

func configureHTTP2ConnHealthCheck(h2Transport *http2.Transport) {
	h2Transport.ReadIdleTimeout = 1 * time.Second
	h2Transport.PingTimeout = 1 * time.Second
}

func iosAlertDictionary(payload *payload.Payload, req PushNotification) *payload.Payload {
	// Alert dictionary

	if len(req.Title) > 0 {
		payload.AlertTitle(req.Title)
	}

	if len(req.Message) > 0 && len(req.Title) > 0 {
		payload.AlertBody(req.Message)
	}

	if len(req.Alert.Title) > 0 {
		payload.AlertTitle(req.Alert.Title)
	}

	// Apple Watch & Safari display this string as part of the notification interface.
	if len(req.Alert.Subtitle) > 0 {
		payload.AlertSubtitle(req.Alert.Subtitle)
	}

	if len(req.Alert.TitleLocKey) > 0 {
		payload.AlertTitleLocKey(req.Alert.TitleLocKey)
	}

	if len(req.Alert.LocArgs) > 0 {
		payload.AlertLocArgs(req.Alert.LocArgs)
	}

	if len(req.Alert.TitleLocArgs) > 0 {
		payload.AlertTitleLocArgs(req.Alert.TitleLocArgs)
	}

	if len(req.Alert.Body) > 0 {
		payload.AlertBody(req.Alert.Body)
	}

	if len(req.Alert.LaunchImage) > 0 {
		payload.AlertLaunchImage(req.Alert.LaunchImage)
	}

	if len(req.Alert.LocKey) > 0 {
		payload.AlertLocKey(req.Alert.LocKey)
	}

	if len(req.Alert.Action) > 0 {
		payload.AlertAction(req.Alert.Action)
	}

	if len(req.Alert.ActionLocKey) > 0 {
		payload.AlertActionLocKey(req.Alert.ActionLocKey)
	}

	// General
	if len(req.Category) > 0 {
		payload.Category(req.Category)
	}

	if len(req.Alert.SummaryArg) > 0 {
		payload.AlertSummaryArg(req.Alert.SummaryArg)
	}

	if req.Alert.SummaryArgCount > 0 {
		payload.AlertSummaryArgCount(req.Alert.SummaryArgCount)
	}

	return payload
}

// GetIOSNotification use for define iOS notification.
// The iOS Notification Payload
// ref: https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/PayloadKeyReference.html#//apple_ref/doc/uid/TP40008194-CH17-SW1
func GetIOSNotification(req PushNotification) *apns2.Notification {
	notification := &apns2.Notification{
		ApnsID:     req.ApnsID,
		Topic:      req.Topic,
		CollapseID: req.CollapseID,
	}

	if req.Expiration != nil {
		notification.Expiration = time.Unix(*req.Expiration, 0)
	}

	if len(req.Priority) > 0 {
		if req.Priority == "normal" {
			notification.Priority = apns2.PriorityLow
		} else if req.Priority == "high" {
			notification.Priority = apns2.PriorityHigh
		}
	}

	if len(req.PushType) > 0 {
		notification.PushType = apns2.EPushType(req.PushType)
	}

	payload := payload.NewPayload()

	// add alert object if message length > 0 and title is empty
	if len(req.Message) > 0 && req.Title == "" {
		payload.Alert(req.Message)
	}

	// zero value for clear the badge on the app icon.
	if req.Badge != nil && *req.Badge >= 0 {
		payload.Badge(*req.Badge)
	}

	if req.MutableContent {
		payload.MutableContent()
	}

	switch req.Sound.(type) {
	// from http request binding
	case map[string]interface{}:
		result := &Sound{}
		_ = mapstructure.Decode(req.Sound, &result)
		payload.Sound(result)
	// from http request binding for non critical alerts
	case string:
		payload.Sound(&req.Sound)
	case Sound:
		payload.Sound(&req.Sound)
	}

	if len(req.SoundName) > 0 {
		payload.SoundName(req.SoundName)
	}

	if req.SoundVolume > 0 {
		payload.SoundVolume(req.SoundVolume)
	}

	if req.ContentAvailable {
		payload.ContentAvailable()
	}

	if len(req.URLArgs) > 0 {
		payload.URLArgs(req.URLArgs)
	}

	if len(req.ThreadID) > 0 {
		payload.ThreadID(req.ThreadID)
	}

	for k, v := range req.Data {
		payload.Custom(k, v)
	}

	payload = iosAlertDictionary(payload, req)

	notification.Payload = payload

	return notification
}

func getApnsClient(cfg config.ConfYaml, req PushNotification) (*apns2.Client, error) {
	var apns_client, err = InitAPNSClient(cfg, req.ApnsKeyPath, req.ApnsKeyBase64, req.ApnsKeyType, req.ApnsPassword, req.ApnsKeyID, req.ApnsTeamID)
	if err != nil {
		return nil, err
	}

	var client *apns2.Client
	if req.Production {
		client = apns_client.Production()
	} else if req.Development {
		client = apns_client.Development()
	} else {
		if cfg.Ios.Production {
			client = apns_client.Production()
		} else {
			client = apns_client.Development()
		}
	}
	return client, nil
}

// PushToIOS provide send notification to APNs server.
func PushToIOS(req PushNotification) {
	logx.LogAccess.Debug("Start push notification for iOS")

	if req.Cfg.Core.Sync && !core.IsLocalQueue(core.Queue(req.Cfg.Queue.Engine)) {
		req.Cfg.Core.Sync = false
	}

	var (
		retryCount = 0
		maxRetry   = req.Cfg.Ios.MaxRetry
	)

	if req.Retry > 0 && req.Retry < maxRetry {
		maxRetry = req.Retry
	}

Retry:
	var newTokens []string

	notification := GetIOSNotification(req)
	client, err := getApnsClient(req.Cfg, req)

	if err != nil {
		// APNS server error
		logx.LogError.Error("APN server error: " + err.Error())
		return
	}

	var wg sync.WaitGroup
	for _, token := range req.Tokens {
		// occupy push slot
		MaxConcurrentIOSPushes <- struct{}{}
		wg.Add(1)
		go func(notification apns2.Notification, token string) {
			notification.DeviceToken = token

			// send ios notification
			res, err := client.Push(&notification)
			if err != nil || (res != nil && res.StatusCode != http.StatusOK) {
				if err == nil {
					// error message:
					// ref: https://github.com/sideshow/apns2/blob/master/response.go#L14-L65
					err = errors.New(res.Reason)
				}
				// apns server error
				logPush(req.Cfg, core.FailedPush, token, req, err)

				if req.Cfg.Core.Sync {
					req.AddLog(createLogPushEntry(req.Cfg, core.FailedPush, token, req, err))
				} else if req.Cfg.Core.FeedbackURL != "" {
					go func(logger *logrus.Logger, log logx.LogPushEntry, url string, timeout int64) {
						err := DispatchFeedback(log, url, timeout)
						if err != nil {
							logger.Error(err)
						}
					}(logx.LogError, createLogPushEntry(req.Cfg, core.FailedPush, token, req, err), req.Cfg.Core.FeedbackURL, req.Cfg.Core.FeedbackTimeout)
				}

				status.StatStorage.AddIosError(1)
				// We should retry only "retryable" statuses. More info about response:
				// https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/handling_notification_responses_from_apns
				if res != nil && res.StatusCode >= http.StatusInternalServerError {
					newTokens = append(newTokens, token)
				}
			}

			if res != nil && res.Sent() {
				logPush(req.Cfg, core.SucceededPush, token, req, nil)
				status.StatStorage.AddIosSuccess(1)
			}

			// free push slot
			<-MaxConcurrentIOSPushes
			wg.Done()
		}(*notification, token)
	}

	wg.Wait()

	if len(newTokens) > 0 && retryCount < maxRetry {
		retryCount++

		// resend fail token
		req.Tokens = newTokens
		goto Retry
	}
}
