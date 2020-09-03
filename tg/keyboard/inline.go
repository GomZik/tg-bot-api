package keyboard

import "encoding/json"

type InlineButton struct {
	Text         string `json:"text"`
	URL          string `json:"url,omitempty"`
	CallbackData string `json:"callback_data,omitempty"`
}

type InlineMarkup struct {
	Buttons [][]InlineButton `json:"inline_keyboard"`
}

func (im *InlineMarkup) Serialize() ([]byte, error) {
	return json.Marshal(im)
}
