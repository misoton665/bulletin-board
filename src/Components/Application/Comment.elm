module Components.Application.Comment exposing (..)

import Html exposing (Html, div, p, h4, text)

type alias Comment = {author: String, body: String}

toHtml : Comment -> Html a
toHtml comment = div [] [
    p [] [text <| comment.author ++ ": " ++ comment.body]
  ]

toHtmlFromList : List Comment -> Html a
toHtmlFromList comments = div [] <| List.map toHtml comments
