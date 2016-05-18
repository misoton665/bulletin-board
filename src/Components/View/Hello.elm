module Components.View.Hello exposing (..)

import Html exposing (Html, div, text)
import Html.Attributes exposing (class)
import String

import Components.Model.Model exposing (..)

-- hello component
hello : Model -> Html a
hello model = case model of
  Model value ->
    div
      [ class "mt-h2" ]
      [ text ( "Hello, World" ++ ( String.repeat value <| "!" ) ) ]
