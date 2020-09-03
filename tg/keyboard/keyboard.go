package keyboard

import "encoding/json"

type ReplyKeyboardButton struct {
	Text            string `json:"text"`
	RequestContact  bool   `json:"request_contact"`
	RequestLocation bool   `json:"request_location"`
}

type ReplyKeyboard struct {
	Keyboard        [][]ReplyKeyboardButton `json:"keyboard"`
	ResizeKeyboard  bool                    `json:"resize_keyboard"`
	OneTimeKeyboard bool                    `json:"one_time_keyboard"`
	Selective       bool                    `json:"selective"`
}

type ReplyKeyboardButtonOption func(*ReplyKeyboardButton)

func RequestContact() ReplyKeyboardButtonOption {
	return func(b *ReplyKeyboardButton) {
		b.RequestContact = true
	}
}

func RequestLocation() ReplyKeyboardButtonOption {
	return func(b *ReplyKeyboardButton) {
		b.RequestLocation = true
	}
}

func ReplyButton(text string, opts ...ReplyKeyboardButtonOption) ReplyKeyboardButton {
	b := ReplyKeyboardButton{
		Text: text,
	}

	for _, opt := range opts {
		opt(&b)
	}
	return b
}

type ReplyKeyboardOption func(*ReplyKeyboard)

func ResizeKeyboard() ReplyKeyboardOption {
	return func(kb *ReplyKeyboard) {
		kb.ResizeKeyboard = true
	}
}

func OneTimeKeyboard() ReplyKeyboardOption {
	return func(kb *ReplyKeyboard) {
		kb.OneTimeKeyboard = true
	}
}

func Selective() ReplyKeyboardOption {
	return func(kb *ReplyKeyboard) {
		kb.Selective = true
	}
}

func NewReplyKeyboard(opts ...ReplyKeyboardOption) ReplyKeyboard {
	kb := ReplyKeyboard{}
	for _, opt := range opts {
		opt(&kb)
	}

	return kb
}

func (kb *ReplyKeyboard) Row(buttons ...ReplyKeyboardButton) {
	kb.Keyboard = append(kb.Keyboard, buttons)
}

func (kb *ReplyKeyboard) Add(buttons ...ReplyKeyboardButton) {
	for _, btn := range buttons {
		kb.Row(btn)
	}
}

func (kb ReplyKeyboard) Serialize() ([]byte, error) {
	return json.Marshal(kb)
}
