package main

import (
	"context"
	"os"

	"github.com/gomzik/tg-bot-api/tg/keyboard"
	"github.com/gomzik/tg-bot-api/tg/message"

	"github.com/gomzik/tg-bot-api/tg"
)

type Bot struct {
	*tg.API
}

func main() {
	token, ok := os.LookupEnv("TELEGRAM_TOKEN")
	if !ok {
		panic("no TELEGRAM_TOKEN env variable")
	}
	api, err := tg.New(token)
	if err != nil {
		panic(err)
	}

	if err := api.Run(&Bot{api}, tg.PollStrategy()); err != nil {
		panic(err)
	}
}

func (b *Bot) HandleUpdate(ctx context.Context, upd tg.Update) error {
	if upd.Message != nil && upd.Message.Text != nil {
		kb := keyboard.NewReplyKeyboard(keyboard.ResizeKeyboard())
		kb.Add(
			keyboard.ReplyButton("Pin location", keyboard.RequestLocation()),
			keyboard.ReplyButton("Share phone", keyboard.RequestContact()),
			keyboard.ReplyButton("Just command"),
		)
		_, err := b.SendMessage(ctx, message.Text(
			upd.Message.Chat.ID,
			"echo: "+*upd.Message.Text,
			message.InReplyTo(upd.Message.ID),
			message.WithKeyboard(kb),
		))
		if err != nil {
			return err
		}
		ikb := keyboard.NewInlineMarkupKeyboard()
		ikb.Row(
			keyboard.InlineButton("Like", keyboard.CallbackData("like")),
			keyboard.InlineButton("Dislike", keyboard.CallbackData("dislike")),
		)
		ikb.Row(
			keyboard.InlineButton("Comments", keyboard.URL("https://example.com")),
		)
		_, err = b.SendMessage(ctx, message.Text(
			upd.Message.Chat.ID,
			"InlineButtons:",
			message.WithKeyboard(ikb),
		))
		if err != nil {
			return err
		}
	}

	if upd.CallbackQuery != nil {
		_, err := b.UpdateMessage(ctx, upd.CallbackQuery.Message.ID, message.Text(
			upd.CallbackQuery.Message.Chat.ID, "Clicked!"))
		if err != nil {
			return err
		}
	}
	return nil
}
