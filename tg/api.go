package tg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/gomzik/tg-bot-api/tg/file"
	"github.com/gomzik/tg-bot-api/tg/message"
	"github.com/gomzik/tg-bot-api/tg/user"

	"golang.org/x/sync/errgroup"
)

var (
	tgBaseURL *url.URL
)

type TelegramError struct {
	StatusCode int
}

func (t TelegramError) Error() string {
	return fmt.Sprintf("telegram returned non 200 ok status code: %d", t.StatusCode)
}

func init() {
	u, err := url.Parse("https://api.telegram.org")
	if err != nil {
		panic(err)
	}
	tgBaseURL = u
}

type Logger interface {
	Printf(string, ...interface{})
}

type API struct {
	token      string
	httpClient *http.Client
	logger     Logger
	botData    BotUser
}

type Option func(*API)

func HTTPClient(c *http.Client) Option {
	return func(a *API) {
		a.httpClient = c
	}
}

func WithLogger(logger Logger) Option {
	return func(a *API) {
		a.logger = logger
	}
}

type NoOpLogger struct{}

func (NoOpLogger) Printf(string, ...interface{}) {}

func New(token string, options ...Option) (*API, error) {
	api := API{
		token:      token,
		httpClient: http.DefaultClient,
		logger:     NoOpLogger{},
	}

	for _, opt := range options {
		opt(&api)
	}

	botData, err := api.GetMe(context.Background())
	if err != nil {
		return nil, err
	}
	api.botData = *botData
	return &api, err
}

type BotUser struct {
	user.User
	Username                string `json:"username"`
	CanJoinGroups           bool   `json:"can_join_groups"`
	CanReadAllGroupMessages bool   `json:"can_read_all_group_messages"`
	SupportsInlineQueries   bool   `json:"supports_inline_queries"`
}

type tgFile struct {
	r *http.Response
}

func (f *tgFile) Read(b []byte) (int, error) {
	return f.r.Body.Read(b)
}

func (f *tgFile) Close() error {
	io.Copy(ioutil.Discard, f.r.Body)
	return f.r.Body.Close()
}

var (
	_ io.ReadCloser = (*tgFile)(nil)
)

func (api *API) newFileRequest(ctx context.Context, filePath string) (*http.Request, error) {
	u, err := url.Parse(filePath)
	if err != nil {
		return nil, err
	}

	u.Path = path.Join("file", fmt.Sprintf("bot%s", api.token), u.Path)
	u = tgBaseURL.ResolveReference(u)

	api.logger.Printf("tg: GET -> %s", strings.ReplaceAll(u.String(), api.token, "*****"))

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	return req, err
}

func (api *API) newMultipartRequest(ctx context.Context, relURL string, body map[string]interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	mp := multipart.NewWriter(&buf)
	for k, v := range body {
		switch v := v.(type) {
		case io.ReadCloser:
			w, err := mp.CreateFormFile(k, k)
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(w, v); err != nil {
				return nil, err
			}
		case string:
			w, err := mp.CreateFormField(k)
			if err != nil {
				return nil, err
			}
			if _, err := w.Write([]byte(v)); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("non string or io.ReadCloser fields are not supported now. Convert them to strings")
		}
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "multipart/form-data")

	u, err := url.Parse(relURL)
	if err != nil {
		return nil, err
	}

	u.Path = path.Join(fmt.Sprintf("bot%s", api.token), u.Path)
	u = tgBaseURL.ResolveReference(u)

	api.logger.Printf("tg: %s -> %s", "POST", strings.ReplaceAll(u.String(), api.token, "*****"))

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	api.logger.Printf("tg: headers: %+v", headers)
	return req, nil
}

func (api *API) newRequest(ctx context.Context, method, relURL string, body interface{}) (*http.Request, error) {
	var bodyReader io.Reader
	headers := make(http.Header)
	headers.Set("Accept", "application/json")

	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
		bodyReader = &buf
		api.logger.Printf("tg: body is %s", buf.String())
		headers.Set("Content-Type", "application/json")
	}

	u, err := url.Parse(relURL)
	if err != nil {
		return nil, err
	}

	u.Path = path.Join(fmt.Sprintf("bot%s", api.token), u.Path)
	u = tgBaseURL.ResolveReference(u)

	api.logger.Printf("tg: %s -> %s", method, strings.ReplaceAll(u.String(), api.token, "*****"))

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	api.logger.Printf("tg: headers: %+v", headers)
	return req, nil
}

type tgResponse struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
}

func (api *API) do(r *http.Request, dst interface{}) error {
	resp, err := api.httpClient.Do(r)
	if err != nil {
		return err
	}

	// DEBUG
	var debugBuf bytes.Buffer
	rdr := io.TeeReader(resp.Body, &debugBuf)
	defer func() {
		if debugBuf.Len() > 0 {
			api.logger.Printf("tg response: %s", debugBuf.String())
		}
	}()

	defer func() {
		io.Copy(ioutil.Discard, rdr)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return TelegramError{
			StatusCode: resp.StatusCode,
		}
	}

	if dst != nil {
		var rsp tgResponse
		if err := json.NewDecoder(rdr).Decode(&rsp); err != nil {
			return err
		}
		if !rsp.OK {
			return fmt.Errorf("tg: response not ok")
		}
		if err := json.Unmarshal(rsp.Result, dst); err != nil {
			return err
		}
	}

	return nil
}

func (api *API) GetMe(ctx context.Context) (*BotUser, error) {
	req, err := api.newRequest(ctx, "GET", "getMe", nil)
	if err != nil {
		return nil, err
	}

	var resp BotUser
	if err := api.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (api *API) Username() string {
	return api.botData.Username
}

type Update struct {
	ID            int              `json:"update_id"`
	Message       *message.Message `json:"message"`
	CallbackQuery *CallbackQuery   `json:"callback_query"`
}

type CallbackQuery struct {
	ID      string           `json:"id"`
	From    user.User        `json:"from"`
	Message *message.Message `json:"message"`
	Data    string           `json:"data"`
}

func (api *API) GetUpdatesContext(ctx context.Context, offset int) ([]Update, error) {
	prms := make(url.Values)
	prms.Add("timeout", "600")
	if offset != 0 {
		prms.Add("offset", strconv.Itoa(offset))
	}
	u := &url.URL{
		Path:     "getUpdates",
		RawQuery: prms.Encode(),
	}
	req, err := api.newRequest(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	var res []Update
	if err := api.do(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type Handler interface {
	HandleUpdate(context.Context, Update) error
}

type HandlerFunc func(context.Context, Update) error

func (h HandlerFunc) HandleUpdate(ctx context.Context, upd Update) error {
	return h(ctx, upd)
}

type ReceiveStrategy interface {
	run(ctx context.Context, api *API) error
	getUpdatesChan() <-chan Update
}

type pollStrategy struct {
	updates chan Update
}

func (ps *pollStrategy) getUpdatesChan() <-chan Update {
	return ps.updates
}

func (ps *pollStrategy) run(ctx context.Context, api *API) error {
	offset := 0
	for {
		upds, err := api.GetUpdatesContext(ctx, offset)
		if err != nil {
			return err
		}
		for _, upd := range upds {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ps.updates <- upd:
				offset = upd.ID + 1
			}
		}
	}
}

func PollStrategy() ReceiveStrategy {
	return &pollStrategy{
		updates: make(chan Update),
	}
}

type CertType int

const (
	SelfSignedCert CertType = iota
	LetsEncryptCert
	CustomCert
)

type webhookStrategy struct {
	publicURL      string
	useSSL         bool
	maxConnections int
	certType       CertType
	keyPath        string
	certPath       string
	leEmail        string
	methods        []string
	listenAddr     *string

	updates chan Update
}

func (ws *webhookStrategy) run(ctx context.Context, api *API) (err error) {
	handler := ws.getTelegramWebhookHandler(ctx, api)
	listenAddr := ":80"
	run := http.ListenAndServe

	if ws.useSSL {
		listenAddr = ":443"
		switch ws.certType {
		case SelfSignedCert:
			run, err = ws.wrapSelfSignedHandler(ctx, api)
		case LetsEncryptCert:
			run, err = ws.wrapAcmeHandler(ctx, api)
		case CustomCert:
			run, err = ws.getTLSHandler(ctx, api)
		default:
			err = fmt.Errorf("unknown certType %v", ws.certType)
		}
		if err != nil {
			return err
		}
	}
	if ws.listenAddr != nil {
		listenAddr = *ws.listenAddr
	}
	return run(listenAddr, handler)
}

func (ws *webhookStrategy) getUpdatesChan() <-chan Update {
	return ws.updates
}

func (ws *webhookStrategy) getTelegramWebhookHandler(ctx context.Context, api *API) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Trim(r.URL.Path, "/") != api.token {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		var upd Update
		if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
			api.logger.Printf("tg: [ERROR] got non valid update: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		ws.updates <- upd
	})
}

type runFn func(string, http.Handler) error

func (ws *webhookStrategy) wrapSelfSignedHandler(ctx context.Context, next http.Handler) (runFn, error) {
	// TODO: submit self signed certificate to telegram
	return func(addr string, handler http.Handler) error {
		srv := http.Server{
			Handler: handler,
			Addr:    addr,
		}
		return srv.ListenAndServeTLS(ws.certPath, ws.keyPath)
	}, nil
}

type WebhookOption func(*webhookStrategy)

func UseLetsEncryptCert(email, p string) WebhookOption {
	return func(ws *webhookStrategy) {
		ws.useSSL = true
		ws.certPath = path.Join(p, "cert.crt")
		ws.keyPath = path.Join(p, "cert.key")
		ws.leEmail = email
		ws.certType = LetsEncryptCert
	}
}

func UseSelfSignedCert(p string) WebhookOption {
	return func(ws *webhookStrategy) {
		ws.useSSL = true
		ws.certPath = path.Join(p, "cert.crt")
		ws.keyPath = path.Join(p, "cert.key")
		ws.certType = SelfSignedCert
	}
}

func UseCustomCert(pathToCert, pathToKey string) WebhookOption {
	return func(ws *webhookStrategy) {
		ws.useSSL = true
		ws.certPath = pathToCert
		ws.keyPath = pathToKey
		ws.certType = CustomCert
	}
}

func NoSSL() WebhookOption {
	return func(ws *webhookStrategy) {
		ws.useSSL = false
	}
}

func ListenAddr(addr string) WebhookOption {
	return func(ws *webhookStrategy) {
		ws.listenAddr = &addr
	}
}

func WebhookStrategy(publicURL string, options ...WebhookOption) ReceiveStrategy {
	tdir := os.TempDir()
	ws := webhookStrategy{
		useSSL:   true,
		certType: SelfSignedCert,
		certPath: path.Join(tdir, "telegram-bot.crt"),
		keyPath:  path.Join(tdir, "telegram-bot.key"),

		updates: make(chan Update),
	}
	for _, opt := range options {
		opt(&ws)
	}
	return &ws
}

func (api *API) Run(h Handler, s ReceiveStrategy) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := api.RemoveWebhook(ctx); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	ch := s.getUpdatesChan()
	g.Go(func() error {
		return s.run(ctx, api)
	})

	g.Go(func() error {
		for {
			select {
			case upd, ok := <-ch:
				if !ok {
					return nil
				}
				if err := h.HandleUpdate(ctx, upd); err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})

	return g.Wait()
}

func (api *API) SendMessage(ctx context.Context, msg *message.Message) (*message.Message, error) {
	req := struct {
		ChatID           int64           `json:"chat_id"`
		Text             string          `json:"text"`
		ReplyToMessageID int             `json:"reply_to_message_id"`
		ReplyMarkup      json.RawMessage `json:"reply_markup,omitempty"`
		ParseMode        string          `json:"parse_mode"`
	}{
		ChatID: msg.Chat.ID,
	}

	if msg.Markdown {
		req.ParseMode = "MarkdownV2"
	}

	if msg.Text != nil {
		req.Text = *msg.Text
	}

	if msg.ReplyToMessage != nil {
		req.ReplyToMessageID = msg.ReplyToMessage.ID
	}

	if msg.ReplyMarkup != nil {
		d, err := msg.ReplyMarkup.Serialize()
		if err != nil {
			return nil, err
		}
		req.ReplyMarkup = d
	}

	r, err := api.newRequest(ctx, "POST", "sendMessage", &req)
	if err != nil {
		return nil, err
	}

	var resp message.Message
	if err := api.do(r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (api *API) GetFile(ctx context.Context, fileID string) (*file.File, error) {
	req := struct {
		FileID string `json:"file_id"`
	}{
		FileID: fileID,
	}

	r, err := api.newRequest(ctx, "POST", "getFile", &req)
	if err != nil {
		return nil, err
	}

	var resp file.File
	if err := api.do(r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (api *API) GetFD(ctx context.Context, fileID string) (io.ReadCloser, error) {
	f, err := api.GetFile(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if f.FilePath == nil {
		return nil, fmt.Errorf("tg: telegram servers does not return file_path")
	}

	req, err := api.newFileRequest(ctx, *f.FilePath)
	if err != nil {
		return nil, err
	}

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return &tgFile{resp}, nil
}

func (api *API) UpdateMessage(ctx context.Context, messageID int, newMsg *message.Message) (*message.Message, error) {
	body := struct {
		ChatID      int64           `json:"chat_id"`
		MessageID   int             `json:"message_id"`
		Text        string          `json:"text"`
		ParseMode   string          `json:"parse_mode,omitempty"`
		ReplyMarkup json.RawMessage `json:"reply_markup,omitempty"`
	}{
		ChatID:    newMsg.Chat.ID,
		MessageID: messageID,
		Text:      *newMsg.Text,
	}

	if newMsg.Markdown {
		body.ParseMode = "MarkdownV2"
	}

	if newMsg.ReplyMarkup != nil {
		kb, err := newMsg.ReplyMarkup.Serialize()
		if err != nil {
			return nil, err
		}
		body.ReplyMarkup = kb
	}

	req, err := api.newRequest(ctx, "POST", "editMessageText", &body)
	if err != nil {
		return nil, err
	}

	var res message.Message
	if err := api.do(req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (api *API) RemoveWebhook(ctx context.Context) error {
	req, err := api.newRequest(ctx, "POST", "deleteWebhook", nil)
	if err != nil {
		return err
	}

	if err := api.do(req, nil); err != nil {
		return err
	}
	return nil
}

type SetWebhookParams struct {
	maxConnections int
	allowedUpdates []string
	certificate    io.ReadCloser
}

type SetWebhookOption func(*SetWebhookParams)

func CustomCertificate(f io.ReadCloser) SetWebhookOption {
	return func(p *SetWebhookParams) {
		p.certificate = f
	}
}

func MaxConnections(i int) SetWebhookOption {
	if i > 100 {
		i = 100
	}

	if i < 1 {
		i = 1
	}

	return func(p *SetWebhookParams) {
		p.maxConnections = i
	}
}

func AllowedUpadte(s string) SetWebhookOption {
	return func(p *SetWebhookParams) {
		p.allowedUpdates = append(p.allowedUpdates, s)
	}
}

func (api *API) SetWebhook(ctx context.Context, url string, options ...SetWebhookOption) error {
	var params SetWebhookParams
	for _, opt := range options {
		opt(&params)
	}

	reqData := struct {
		URL            string   `json:"url"`
		MaxConnections int      `json:"max_connections,omitempty"`
		AllowedUpdates []string `json:"allowed_updates,omitempty"`
	}{
		URL:            url,
		MaxConnections: params.maxConnections,
		AllowedUpdates: params.allowedUpdates,
	}
	req, err := api.newRequest(ctx, "POST", "setWebhook", reqData)
	if err != nil {
		return err
	}

	if err := api.do(req, nil); err != nil {
		return err
	}

	return nil
}
