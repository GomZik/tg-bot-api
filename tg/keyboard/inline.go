package keyboard

import "encoding/json"

type InlineButtonItem struct {
	Text         string `json:"text"`
	URL          string `json:"url,omitempty"`
	CallbackData string `json:"callback_data,omitempty"`
}

type InlineButtonOption func(*InlineButtonItem)

func URL(u string) InlineButtonOption {
	return func(b *InlineButtonItem) {
		b.CallbackData = ""
		b.URL = u
	}
}

func CallbackData(data string) InlineButtonOption {
	return func(b *InlineButtonItem) {
		b.URL = ""
		b.CallbackData = data
	}
}

func InlineButton(text string, options ...InlineButtonOption) InlineButtonItem {
	b := InlineButtonItem{Text: text}

	for _, opt := range options {
		opt(&b)
	}

	return b
}

type InlineMarkup struct {
	Buttons [][]InlineButtonItem `json:"inline_keyboard"`
}

func (im InlineMarkup) Serialize() ([]byte, error) {
	return json.Marshal(im)
}

func NewInlineMarkupKeyboard() InlineMarkup {
	return InlineMarkup{}
}

func (m *InlineMarkup) Row(buttons ...InlineButtonItem) {
	m.Buttons = append(m.Buttons, buttons)
}

func (m *InlineMarkup) Add(buttons ...InlineButtonItem) {
	for _, btn := range buttons {
		m.Row(btn)
	}
}
