package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gomzik/tg-bot-api/tg/keyboard"
	"github.com/gomzik/tg-bot-api/tg/message"
	"golang.org/x/sync/errgroup"

	"github.com/gomzik/tg-bot-api/tg"
)

type Bot struct {
	*tg.API
}

func httpErr(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

func handleWebhook(token string, api *tg.API) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/") != token {
			httpErr(w, http.StatusNotFound)
			return
		}

		if err := api.FeedRequest(r); err != nil {
			log.Println(err.Error())
			httpErr(w, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}

func main() {
	token, ok := os.LookupEnv("TELEGRAM_TOKEN")
	if !ok {
		panic("no TELEGRAM_TOKEN env variable")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	publicURL, ok := os.LookupEnv("PUBLIC_URL")
	if !ok {
		panic("no PUBLIC_URL are set")
	}

	api, err := tg.New(token)
	if err != nil {
		panic(err)
	}

	var g errgroup.Group

	srv := http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: handleWebhook(token, api),
	}
	g.Go(func() error {
		return srv.ListenAndServe()
	})

	api.SetHandler(&Bot{api})
	if err := api.RemoveWebhook(context.Background()); err != nil {
		panic(err)
	}

	if err := api.SetWebhook(context.Background(), fmt.Sprintf("%s/%s", publicURL, token)); err != nil {
		panic(err)
	}
	defer func() {
		if err := api.RemoveWebhook(context.Background()); err != nil {
			panic(err)
		}
	}()

	if err := g.Wait(); err != nil {
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
