module Comment exposing (..)

import Html exposing (Html, div, h3, h4, text)

import Components.Update.Update as U

type alias Comment = {author: String, body: String}

toHtml : Comment -> Html (U.Message)
toHtml comment = div [] [
    h3 [] [text comment.author],
    h4 [] [text comment.body]
  ]

toHtmlFromList : List Comment -> Html (U.Message)
toHtmlFromList comments = div [] <| List.map toHtml comments