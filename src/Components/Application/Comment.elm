module Components.Application.Comment exposing (..)

import Html exposing (Html, div, h3, h4, text)

type alias Comment = {author: String, body: String}

toHtml : Comment -> Html a
toHtml comment = div [] [
    h3 [] [text comment.author],
    h4 [] [text comment.body]
  ]

toHtmlFromList : List Comment -> Html a
toHtmlFromList comments = div [] <| List.map toHtml comments
