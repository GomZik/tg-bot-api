package tg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/gomzik/tg-bot-api/tg/message"
	"github.com/gomzik/tg-bot-api/tg/user"

	"github.com/gomzik/tg-bot-api/tg/file"
)

var (
	tgBaseURL *url.URL
)

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
	handler    Handler
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
		return fmt.Errorf("tg: failed to request telegram api: returned not 200 OK")
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

func (api *API) SetHandler(h Handler) {
	api.handler = h
}

func (api *API) Poll() error {
	if api.handler == nil {
		return fmt.Errorf("handler not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	offset := 0

	for {
		upds, err := api.GetUpdatesContext(ctx, offset)
		if err != nil {
			return err
		}
		for _, upd := range upds {
			if err := api.handler.HandleUpdate(ctx, upd); err != nil {
				return err
			}
			offset = upd.ID + 1
		}
	}
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

type WebhookParams struct {
	maxConnections int
	allowedUpdates []string
}

type WebhookOption func(*WebhookParams)

func MaxConnections(i int) WebhookOption {
	if i > 100 {
		i = 100
	}

	if i < 1 {
		i = 1
	}

	return func(p *WebhookParams) {
		p.maxConnections = i
	}
}

func AllowedUpadte(s string) WebhookOption {
	return func(p *WebhookParams) {
		p.allowedUpdates = append(p.allowedUpdates, s)
	}
}

func (api *API) SetWebhook(ctx context.Context, url string, options ...WebhookOption) error {
	var params WebhookParams
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

// FeedRequest used to pass webhook request
func (api *API) FeedRequest(r *http.Request) error {
	if api.handler == nil {
		return fmt.Errorf("no handler set")
	}

	var upd Update
	if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
		return fmt.Errorf("failed to decode update: %w", err)
	}

	return api.handler.HandleUpdate(r.Context(), upd)
}
